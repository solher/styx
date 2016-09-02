package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	redigo "github.com/garyburd/redigo/redis"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/pressly/chi"
	"github.com/solher/styx/account"
	"github.com/solher/styx/config"
	"github.com/solher/styx/memory"
	"github.com/solher/styx/redis"
	"sourcegraph.com/sourcegraph/appdash"
	appdashot "sourcegraph.com/sourcegraph/appdash/opentracing"
)

const (
	defaultHTTPAddr     = ":3000"
	defaultGRPCAddr     = ":8082"
	defaultAppdashAddr  = ""
	defaultConfigFile   = "./config.yml"
	defaultRedisAddr    = "redis:6379"
	defaultRedisMaxConn = 16
)

func main() {
	var (
		httpAddrEnv     = envString("HTTP_ADDR", defaultHTTPAddr)
		grpcAddrEnv     = envString("GRPC_ADDR", defaultGRPCAddr)
		appdashAddrEnv  = envString("APPDASH_ADDR", defaultAppdashAddr)
		configFileEnv   = envString("CONFIG_FILE", defaultConfigFile)
		redisAddrEnv    = envString("REDIS_ADDR", defaultRedisAddr)
		redisMaxConnEnv = envInt("REDIS_MAX_CONN", defaultRedisMaxConn)

		httpAddr     = flag.String("httpAddr", httpAddrEnv, "HTTP listen address")
		_            = flag.String("grpcAddr", grpcAddrEnv, "gRPC (HTTP) listen address")
		appdashAddr  = flag.String("appdashAddr", appdashAddrEnv, "Enable Appdash tracing via server host:port")
		configFile   = flag.String("configFile", configFileEnv, "Config file location")
		redisAddr    = flag.String("redisAddr", redisAddrEnv, "Redis server address")
		redisMaxConn = flag.Int("redisMaxConn", redisMaxConnEnv, "Max simultaneous connections to Redis")
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

	// Databases.
	redisPool := &redigo.Pool{
		Dial: func() (redigo.Conn, error) {
			return redigo.Dial("tcp", *redisAddr)
		},
		TestOnBorrow: func(c redigo.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
		MaxIdle: *redisMaxConn,
	}
	defer redisPool.Close()

	// Business domain.
	policyRepo := memory.NewPolicyRepository()
	resourceRepo := memory.NewResourceRepository()

	var accountService account.Service
	{
		sessionRepo := redis.NewSessionRepository(redisPool)
		accountService = account.NewService(sessionRepo)
	}

	// Endpoint domain.
	var createSessionEndpoint endpoint.Endpoint
	{
		createSessionEndpoint = account.MakeCreateSessionEndpoint(accountService)
	}
	var findSessionByTokenEndpoint endpoint.Endpoint
	{
		findSessionByTokenEndpoint = account.MakeFindSessionByTokenEndpoint(accountService)
	}
	var deleteSessionByTokenEndpoint endpoint.Endpoint
	{
		deleteSessionByTokenEndpoint = account.MakeDeleteSessionByTokenEndpoint(accountService)
	}
	var deleteSessionsByOwnerTokenEndpoint endpoint.Endpoint
	{
		deleteSessionsByOwnerTokenEndpoint = account.MakeDeleteSessionsByOwnerTokenEndpoint(accountService)
	}

	accountEndpoints := account.Endpoints{
		CreateSessionEndpoint:              createSessionEndpoint,
		FindSessionByTokenEndpoint:         findSessionByTokenEndpoint,
		DeleteSessionByTokenEndpoint:       deleteSessionByTokenEndpoint,
		DeleteSessionsByOwnerTokenEndpoint: deleteSessionsByOwnerTokenEndpoint,
	}

	// Mechanical domain.
	ctx := context.Background()
	errc := make(chan error)

	// Transport domain.
	accountHandler := account.MakeHTTPHandler(ctx, accountEndpoints, tracer, logger)

	r := chi.NewRouter()
	r.Mount("/account", accountHandler)

	conn, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		logger.Log("err", errors.Wrap(err, "could not create a TCP connection"))
		exitCode = 1
		return
	}
	defer conn.Close()
	logger.Log("msg", "listening on "+*httpAddr+" (HTTP)")
	go func() {
		if err := http.Serve(conn, r); err != nil {
			errc <- errors.Wrap(err, "the http server returned an error")
			return
		}
	}()

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

func envString(env, fallback string) string {
	e := os.Getenv(env)
	if e == "" {
		return fallback
	}
	return e
}

func envInt(env string, fallback int) int {
	e := os.Getenv(env)
	i, err := strconv.Atoi(e)
	if e == "" || err != nil {
		return fallback
	}
	return i
}
