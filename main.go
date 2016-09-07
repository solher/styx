//go:generate protoc -I ./pb ./pb/*.proto --go_out=plugins=grpc:pb
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
	// Tracing domain.
	defaultZipkinAddr = ""
	// Database domain.
	defaultRedisAddr    = "redis:6379"
	defaultRedisMaxConn = 16
	// Business domain.
	// Account service.
	defaultDefaultTokenLength     = 64
	defaultDefaultSessionValidity = 24 * time.Hour
	// Authorization service.
	defaultAccessTokenCookie     = "access_token"
	defaultAccessTokenHeader     = "Styx-Access-Token"
	defaultPayloadHeader         = "Styx-Payload"
	defaultSessionHeader         = "Styx-Session"
	defaultRedirectURLHeader     = "Redirect-Url"
	defaultRedirectURLQueryParam = "redirectUrl"
	defaultRequestURLHeader      = "Request-Url"
	// Transport domain.
	defaultHTTPAddr = ":3000"
	defaultGRPCAddr = ":8082"
	// Config watcher.
	defaultConfigFile = "./config.yml"
)

func main() {
	var (
		// Tracing domain.
		zipkinAddrEnv = envString("ZIPKIN_ADDR", defaultZipkinAddr)
		// Database domain.
		redisAddrEnv    = envString("REDIS_ADDR", defaultRedisAddr)
		redisMaxConnEnv = envInt("REDIS_MAX_CONN", defaultRedisMaxConn)
		// Business domain.
		// Account service.
		defaultTokenLengthEnv     = envInt("DEFAULT_TOKEN_LENGTH", defaultDefaultTokenLength)
		defaultSessionValidityEnv = envDuration("DEFAULT_SESSION_VALIDITY", defaultDefaultSessionValidity)
		// Authorization service.
		accessTokenCookieEnv     = envString("ACCESS_TOKEN_COOKIE", defaultAccessTokenCookie)
		accessTokenHeaderEnv     = envString("ACCESS_TOKEN_HEADER", defaultAccessTokenHeader)
		payloadHeaderEnv         = envString("PAYLOAD_HEADER", defaultPayloadHeader)
		sessionHeaderEnv         = envString("SESSION_HEADER", defaultSessionHeader)
		redirectURLHeaderEnv     = envString("REDIRECT_URL_HEADER", defaultRedirectURLHeader)
		redirectURLQueryParamEnv = envString("REDIRECT_URL_QUERY_PARAM", defaultRedirectURLQueryParam)
		requestURLHeaderEnv      = envString("REQUEST_URL_HEADER", defaultRequestURLHeader)
		// Transport domain.
		httpAddrEnv = envString("HTTP_ADDR", defaultHTTPAddr)
		grpcAddrEnv = envString("GRPC_ADDR", defaultGRPCAddr)
		// Config watcher.
		configFileEnv = envString("CONFIG_FILE", defaultConfigFile)
	)

	var (
		// Tracing domain.
		zipkinAddr = flag.String("zipkinAddr", zipkinAddrEnv, "Enable Zipkin tracing via server host:port")
		// Database domain.
		redisAddr    = flag.String("redisAddr", redisAddrEnv, "Redis server address")
		redisMaxConn = flag.Int("redisMaxConn", redisMaxConnEnv, "Max simultaneous connections to Redis")
		// Business domain.
		// Account service.
		defaultTokenLength     = flag.Int("defaultTokenLength", defaultTokenLengthEnv, "The default session token length")
		defaultSessionValidity = flag.Duration("defaultSessionValidity", defaultSessionValidityEnv, "The default session validity duration")
		// Authorization service.
		accessTokenCookie     = flag.String("accessTokenCookie", accessTokenCookieEnv, "The cookie key to get the access token from")
		accessTokenHeader     = flag.String("accessTokenHeader", accessTokenHeaderEnv, "The HTTP header to get the access token from")
		payloadHeader         = flag.String("payloadHeader", payloadHeaderEnv, "The HTTP header where the session payload is set when access is granted")
		sessionHeader         = flag.String("sessionHeader", sessionHeaderEnv, "The HTTP header where the session is set when access is granted")
		redirectURLHeader     = flag.String("redirectURLHeader", redirectURLHeaderEnv, "The HTTP header where the redirect URL (the original user request URL) is set")
		redirectURLQueryParam = flag.String("redirectURLQueryParam", redirectURLQueryParamEnv, "The query parameter where the redirect URL (the original user request URL) is set")
		requestURLHeader      = flag.String("requestURLHeader", requestURLHeaderEnv, "The HTTP header to get the URL requested by the user")
		// Transport domain.
		httpAddr = flag.String("httpAddr", httpAddrEnv, "HTTP listen address")
		_        = flag.String("grpcAddr", grpcAddrEnv, "gRPC (HTTP) listen address")
		// Config watcher.
		configFile = flag.String("configFile", configFileEnv, "Config file location")
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
			tracer, err = zipkin.NewTracer(zipkin.NewRecorder(collector, false, "styx"+*httpAddr, "styx"))
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
	sessionRepo := redis.NewSessionRepository(
		redisPool,
		redis.DefaultTokenLength(*defaultTokenLength),
		redis.DefaultSessionValidity(*defaultSessionValidity),
	)
	var authorizationService authorization.Service
	{
		authorizationService = authorization.NewService(policyRepo, resourceRepo, sessionRepo)
	}
	var accountService account.Service
	{
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
	authorizationHandler := authorization.MakeHTTPHandler(
		ctx,
		authorizationEndpoints,
		tracer,
		logger,
		authorization.AccessTokenCookie(*accessTokenCookie),
		authorization.AccessTokenHeader(*accessTokenHeader),
		authorization.PayloadHeader(*payloadHeader),
		authorization.SessionHeader(*sessionHeader),
		authorization.RedirectURLHeader(*redirectURLHeader),
		authorization.RedirectURLQueryParam(*redirectURLQueryParam),
		authorization.RequestURLHeader(*requestURLHeader),
	)
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

func envDuration(env string, fallback time.Duration) time.Duration {
	e := os.Getenv(env)
	i, err := time.ParseDuration(e)
	if e == "" || err != nil {
		return fallback
	}
	return i
}
