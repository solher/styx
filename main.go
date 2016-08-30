package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/go-kit/kit/log"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/solher/styx/config"
	"github.com/solher/styx/memory"
	"sourcegraph.com/sourcegraph/appdash"
	appdashot "sourcegraph.com/sourcegraph/appdash/opentracing"
)

func main() {
	var (
		// httpAddr    = flag.String("http.addr", ":3000", "Address for HTTP server")
		// grpcAddr    = flag.String("grpc.addr", ":8082", "gRPC (HTTP) listen address")
		appdashAddr = flag.String("appdash.addr", "", "Enable Appdash tracing via server host:port")
		configFile  = flag.String("configfile", "./config.yml", "Config file location")
	)
	flag.Parse()

	exitCode := 0
	defer func() {
		os.Exit(exitCode)
	}()

	// Logging domain.
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.NewContext(logger).With("ts", log.DefaultTimestampUTC)
		logger = log.NewContext(logger).With("caller", log.DefaultCaller)
	}

	// Tracing domain.
	var tracer stdopentracing.Tracer
	{
		if *appdashAddr != "" {
			logger := log.NewContext(logger).With("tracer", "Appdash")
			logger.Log("msg", "sending trace to "+*appdashAddr)
			tracer = appdashot.NewTracer(appdash.NewRemoteCollector(*appdashAddr))
		} else {
			logger := log.NewContext(logger).With("tracer", "none")
			logger.Log("msg", "tracing disabled")
			tracer = stdopentracing.GlobalTracer() // no-op
		}
	}
	_ = tracer

	// Business domain.
	policyRepo := memory.NewPolicyRepository()
	resourceRepo := memory.NewResourceRepository()

	// Mechanical domain.
	ctx := context.Background()
	errc := make(chan error)
	_ = ctx

	// Config watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Log("err", errors.Wrap(err, "could not create file watcher"))
		exitCode = 1
		return
	}
	defer watcher.Close()
	if err := watcher.Add(*configFile); err != nil {
		logger.Log("err", errors.Wrap(err, "could not add the config file to the watcher"))
		exitCode = 1
		return
	}
	logger.Log("msg", "watching config file at "+*configFile)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					file, err := ioutil.ReadFile(*configFile)
					if err != nil {
						logger.Log("err", errors.Wrap(err, "could not read the config file"))
						continue
					}
					config, err := config.FromFile(file)
					if err != nil {
						logger.Log("err", err)
						continue
					}
					if err := memory.SetPolicies(policyRepo, config.Policies); err != nil {
						logger.Log("err", err)
						continue
					}
					if err := memory.SetResources(resourceRepo, config.Resources); err != nil {
						logger.Log("err", err)
						continue
					}
					logger.Log("msg", "config successfully loaded")
				}
			case err := <-watcher.Errors:
				logger.Log("err", errors.Wrap(err, "watcher returned an error event"))
				continue
			}
		}
	}()
	watcher.Events <- fsnotify.Event{Op: fsnotify.Write} // Triggering manually conf file loading

	// Interrupt handler.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		logger.Log(
			"signal", fmt.Sprintf("%s", <-c),
			"msg", "gracefully shutting down",
		)
		errc <- nil
	}()

	if err := <-errc; err != nil {
		logger.Log("err", err)
		exitCode = 1
	}
}
