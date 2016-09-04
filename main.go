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

	zipkin "github.com/openzipkin/zipkin-go-opentracing"

	"github.com/fsnotify/fsnotify"
	redigo "github.com/garyburd/redigo/redis"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/pressly/chi"
	"github.com/solher/styx/account"
	"github.com/solher/styx/authorization"
	"github.com/solher/styx/config"
	"github.com/solher/styx/helpers"
	"github.com/solher/styx/memory"
	"github.com/solher/styx/redis"
)

const (
	defaultHTTPAddr     = ":3000"
	defaultGRPCAddr     = ":8082"
	defaultZipkinAddr   = ""
	defaultConfigFile   = "./config.yml"
	defaultRedisAddr    = "redis:6379"
	defaultRedisMaxConn = 16
)

func main() {
	var (
		httpAddrEnv     = envString("HTTP_ADDR", defaultHTTPAddr)
		grpcAddrEnv     = envString("GRPC_ADDR", defaultGRPCAddr)
		zipkinAddrEnv   = envString("ZIPKIN_ADDR", defaultZipkinAddr)
		configFileEnv   = envString("CONFIG_FILE", defaultConfigFile)
		redisAddrEnv    = envString("REDIS_ADDR", defaultRedisAddr)
		redisMaxConnEnv = envInt("REDIS_MAX_CONN", defaultRedisMaxConn)

		httpAddr     = flag.String("httpAddr", httpAddrEnv, "HTTP listen address")
		_            = flag.String("grpcAddr", grpcAddrEnv, "gRPC (HTTP) listen address")
		zipkinAddr   = flag.String("zipkinAddr", zipkinAddrEnv, "Enable Zipkin tracing via server host:port")
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
		if *zipkinAddr != "" {
			logger := log.NewContext(logger).With("tracer", "Zipkin")
			logger.Log("msg", "sending trace to "+*zipkinAddr)
			collector, err := zipkin.NewScribeCollector(
				*zipkinAddr,
				3*time.Second,
				zipkin.ScribeLogger(logger),
			)
			if err != nil {
				logger.Log("err", errors.Wrap(err, "could create the Zipkin collector"))
				exitCode = 1
				return
			}
			tracer, err = zipkin.NewTracer(zipkin.NewRecorder(collector, false, "localhost:80", "styx"))
			if err != nil {
				logger.Log("err", errors.Wrap(err, "could not create the Zipkin tracer"))
				exitCode = 1
				return
			}
		} else {
			logger := log.NewContext(logger).With("tracer", "none")
			logger.Log("msg", "tracing disabled")
			tracer = stdopentracing.GlobalTracer() // no-op
		}
	}

	// Database domain.
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
	var authorizationService authorization.Service
	{
		authorizationService = authorization.NewService(policyRepo, resourceRepo)
	}
	var accountService account.Service
	{
		sessionRepo := redis.NewSessionRepository(redisPool)
		accountService = account.NewService(sessionRepo)
	}

	// Endpoint domain.
	var authorizeTokenEndpoint endpoint.Endpoint
	{
		authorizeTokenEndpoint = authorization.MakeAuthorizeTokenEndpoint(authorizationService)
		authorizeTokenEndpoint = helpers.EndpointTracingMiddleware(authorizeTokenEndpoint)
	}
	var redirectEndpoint endpoint.Endpoint
	{
		redirectEndpoint = authorization.MakeRedirectEndpoint(authorizationService)
		redirectEndpoint = helpers.EndpointTracingMiddleware(redirectEndpoint)
	}
	authorizationEndpoints := authorization.Endpoints{
		AuthorizeTokenEndpoint: authorizeTokenEndpoint,
		RedirectEndpoint:       redirectEndpoint,
	}

	var createSessionEndpoint endpoint.Endpoint
	{
		createSessionEndpoint = account.MakeCreateSessionEndpoint(accountService)
		createSessionEndpoint = helpers.EndpointTracingMiddleware(createSessionEndpoint)
	}
	var findSessionByTokenEndpoint endpoint.Endpoint
	{
		findSessionByTokenEndpoint = account.MakeFindSessionByTokenEndpoint(accountService)
		findSessionByTokenEndpoint = helpers.EndpointTracingMiddleware(findSessionByTokenEndpoint)

	}
	var deleteSessionByTokenEndpoint endpoint.Endpoint
	{
		deleteSessionByTokenEndpoint = account.MakeDeleteSessionByTokenEndpoint(accountService)
		deleteSessionByTokenEndpoint = helpers.EndpointTracingMiddleware(deleteSessionByTokenEndpoint)

	}
	var deleteSessionsByOwnerTokenEndpoint endpoint.Endpoint
	{
		deleteSessionsByOwnerTokenEndpoint = account.MakeDeleteSessionsByOwnerTokenEndpoint(accountService)
		deleteSessionsByOwnerTokenEndpoint = helpers.EndpointTracingMiddleware(deleteSessionsByOwnerTokenEndpoint)
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
	authorizationHandler := authorization.MakeHTTPHandler(ctx, authorizationEndpoints, tracer, logger)
	accountHandler := account.MakeHTTPHandler(ctx, accountEndpoints, tracer, logger)

	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	r.Mount("/auth", authorizationHandler)
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
