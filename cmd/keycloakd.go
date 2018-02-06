package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware"
	"github.com/cloudtrust/keycloak-bridge/pkg/user"
	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	keycloak_client "github.com/cloudtrust/keycloak-client/client"
	"github.com/garyburd/redigo/redis"
	sentry "github.com/getsentry/raven-go"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	gokit_influx "github.com/go-kit/kit/metrics/influx"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	"github.com/google/flatbuffers/go"
	"github.com/gorilla/mux"
	influx "github.com/influxdata/influxdb/client/v2"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	jaeger "github.com/uber/jaeger-client-go/config"
	"google.golang.org/grpc"
)

var (
	// Version of the component.
	Version = "1.0.0"
	// Environment is filled by the compiler.
	Environment = "unknown"
	// GitCommit is filled by the compiler.
	GitCommit = "unknown"
)

type mockFlakiService struct{}

func (f *mockFlakiService) NextValidIDString() string {
	return "0"
}

func main() {

	// Logger.
	var logger = log.NewJSONLogger(os.Stdout)
	{
		logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	}

	// Configurations.
	var config = config(log.With(logger, "unit", "config"))
	var (
		componentName = config["component-name"].(string)
		grpcAddr      = config["component-grpc-address"].(string)
		httpAddr      = config["component-http-address"].(string)

		keycloakHTTPConfig = keycloak_client.HttpConfig{
			Addr:     fmt.Sprintf("http://%s", config["keycloak-url"].(string)),
			Username: config["keycloak-username"].(string),
			Password: config["keycloak-password"].(string),
			Timeout:  time.Duration(config["keycloak-timeout-ms"].(int)) * time.Millisecond,
		}

		influxHTTPConfig = influx.HTTPConfig{
			Addr:     fmt.Sprintf("http://%s", config["influx-url"].(string)),
			Username: config["influx-username"].(string),
			Password: config["influx-password"].(string),
		}
		influxBatchPointsConfig = influx.BatchPointsConfig{
			Precision:        config["influx-precision"].(string),
			Database:         config["influx-database"].(string),
			RetentionPolicy:  config["influx-retention-policy"].(string),
			WriteConsistency: config["influx-write-consistency"].(string),
		}
		influxWriteInterval = time.Duration(config["influx-write-interval-ms"].(int)) * time.Millisecond
		jaegerConfig        = jaeger.Configuration{
			Disabled: !config["jaeger"].(bool),
			Sampler: &jaeger.SamplerConfig{
				Type:              config["jaeger-sampler-type"].(string),
				Param:             float64(config["jaeger-sampler-param"].(int)),
				SamplingServerURL: fmt.Sprintf("http://%s", config["jaeger-sampler-url"].(string)),
			},
			Reporter: &jaeger.ReporterConfig{
				LogSpans:            config["jaeger-reporter-logspan"].(bool),
				BufferFlushInterval: time.Duration(config["jaeger-write-interval-ms"].(int)) * time.Millisecond,
			},
		}

		redisURL           = config["redis-url"].(string)
		redisPassword      = config["redis-password"].(string)
		redisDatabase      = config["redis-database"].(int)
		redisWriteInterval = time.Duration(config["redis-write-interval-ms"].(int)) * time.Millisecond

		sentryDSN = fmt.Sprintf(config["sentry-dsn"].(string))

		influxEnabled     = config["influx"].(bool)
		sentryEnabled     = config["sentry"].(bool)
		redisEnabled      = config["redis"].(bool)
		pprofRouteEnabled = config["pprof-route-enabled"].(bool)
	)

	// Redis.
	var redisConn redis.Conn
	if redisEnabled {
		var err error
		redisConn, err = redis.Dial("tcp", redisURL, redis.DialDatabase(redisDatabase), redis.DialPassword(redisPassword))
		if err != nil {
			logger.Log("msg", "could not create redis client", "error", err)
			return
		}
		defer redisConn.Close()

		// Create logger that duplicates logs to stdout and redis.
		logger = log.NewJSONLogger(io.MultiWriter(os.Stdout, NewLogstashRedisWriter(redisConn)))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	}
	defer logger.Log("msg", "goodbye")

	// Add component name and version to the logger tags.
	logger = log.With(logger, "component_name", componentName, "component_version", Version)

	// Log component version infos.
	logger.Log("environment", Environment, "git_commit", GitCommit)

	// Critical errors channel.
	var errc = make(chan error)
	go func() {
		var c = make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	// Keycloak client.
	var keycloakClient keycloak_client.Client
	{
		var err error
		keycloakClient, err = keycloak_client.NewHttpClient(keycloakHTTPConfig)
		if err != nil {
			logger.Log("msg", "could not create Keycloak client", "error", err)
			return
		}
	}

	// Sentry.
	type Sentry interface {
		CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
		URL() string
		Close()
	}

	var sentryClient Sentry
	if sentryEnabled {
		var logger = log.With(logger, "unit", "sentry")
		var err error
		sentryClient, err = sentry.New(sentryDSN)
		if err != nil {
			logger.Log("msg", "could not create Sentry client", "error", err)
			return
		}
		defer sentryClient.Close()
	} else {
		sentryClient = &NoopSentry{}
	}

	// Influx client.
	type Metrics interface {
		NewCounter(name string) metrics.Counter
		NewGauge(name string) metrics.Gauge
		NewHistogram(name string) metrics.Histogram
		WriteLoop(c <-chan time.Time)
		Write(bp influx.BatchPoints) error
		Ping(timeout time.Duration) (time.Duration, string, error)
	}

	var influxMetrics Metrics
	if influxEnabled {
		var logger = log.With(logger, "unit", "influx")

		var influxClient, err = influx.NewHTTPClient(influxHTTPConfig)
		if err != nil {
			logger.Log("msg", "could not create Influx client", "error", err)
			return
		}
		defer influxClient.Close()

		var gokitInflux = gokit_influx.New(
			map[string]string{},
			influxBatchPointsConfig,
			log.With(logger, "unit", "go-kit influx"),
		)

		influxMetrics = NewMetrics(influxClient, gokitInflux)
	} else {
		influxMetrics = &NoopMetrics{}
	}

	// Jaeger client.
	var tracer opentracing.Tracer
	{
		var logger = log.With(logger, "unit", "jaeger")
		var closer io.Closer
		var err error

		tracer, closer, err = jaegerConfig.New(componentName)
		if err != nil {
			logger.Log("msg", "could not create Jaeger tracer", "error", err)
			return
		}
		defer closer.Close()

	}

	// User service.
	var keycloakModule user.KeycloakModule
	{
		keycloakModule = user.NewKeycloakModule(keycloakClient)
	}

	var keycloakComponent user.KeycloakComponent
	{
		keycloakComponent = user.NewKeycloakComponent(keycloakModule)
		keycloakComponent = user.MakeComponentLoggingMW(log.With(logger, "svc", "user", "mw", "component"))(keycloakComponent)
	}

	var userEndpoints = user.NewEndpoints(middleware.MakeEndpointCorrelationIDMW(&mockFlakiService{}))

	userEndpoints.MakeGetUsersEndpoint(
		keycloakComponent,
		middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("getusers_endpoint")),
		middleware.MakeEndpointLoggingMW(log.With(logger, "svc", "user", "mw", "endpoint", "unit", "getusers")),
		middleware.MakeEndpointTracingMW(tracer, "getusers_endpoint"),
	)

	// GRPC server.
	go func() {
		var logger = log.With(logger, "transport", "grpc")
		logger.Log("addr", grpcAddr)

		var lis net.Listener
		{
			var err error
			lis, err = net.Listen("tcp", grpcAddr)
			if err != nil {
				logger.Log("msg", "could not initialise listener", "error", err)
				errc <- err
				return
			}
		}

		// NextID.
		var getUsersHandler grpc_transport.Handler
		{
			getUsersHandler = user.MakeGRPCGetUsersHandler(userEndpoints.GetUsersEndpoint)
			getUsersHandler = user.MakeGRPCTracingMW(tracer, "grpc_server_getusers")(getUsersHandler)
		}

		var grpcServer = user.NewGRPCServer(getUsersHandler)
		var userServer = grpc.NewServer(grpc.CustomCodec(flatbuffers.FlatbuffersCodec{}))
		fb.RegisterUserServiceServer(userServer, grpcServer)

		errc <- userServer.Serve(lis)
	}()

	// Event service.
	var consoleModule event.ConsoleModule
	{
		consoleModule = event.NewConsoleModule(log.With(logger, "svc", "event", "module", "console"))
		consoleModule = event.MakeServiceLoggingMiddleware(logger)(consoleModule)
	}

	var statisticModule event.StatisticModule
	{
		statisticModule = event.NewStatisticModule(influxMetrics, influxBatchPointsConfig)
	}

	var adminEventComponent event.AdminEventService
	{
		var fns = [](func(map[string]string) error){consoleModule.Print, statisticModule.Stats}
		adminEventComponent = event.NewAdminEventService(fns, fns, fns, fns)
		adminEventComponent = event.MakeServiceLoggingAdminEventMiddleware(logger)(adminEventComponent)
	}

	var eventComponent event.EventService
	{
		var fns = [](func(map[string]string) error){consoleModule.Print, statisticModule.Stats}
		eventComponent = event.NewEventService(fns, fns)
	}

	var muxComponent event.MuxService
	{
		muxComponent = event.NewMuxService(eventComponent, adminEventComponent)
		muxComponent = event.MakeServiceLoggingMuxMiddleware(logger)(muxComponent)
		muxComponent = event.MakeServiceErrorMiddleware(logger, sentryClient)(muxComponent)

	}

	var eventConsumerEndpoint endpoint.Endpoint
	{
		eventConsumerEndpoint = event.MakeKeycloakEventsEndpoint(muxComponent)
		eventConsumerEndpoint = middleware.MakeEndpointLoggingMW(log.With(logger, "svc", "event", "mw", "endpoint"))(eventConsumerEndpoint)
		eventConsumerEndpoint = middleware.MakeEndpointTracingMiddleware(tracer, "events")(eventConsumerEndpoint)
		eventConsumerEndpoint = middleware.MakeCorrelationIDMiddleware()(eventConsumerEndpoint)
	}
	var eventsEndpoints = event.Endpoints{
		KeycloakEvents: eventConsumerEndpoint,
	}

	/*
		HTTP monitoring routes.
	*/
	go func() {
		var logger = log.With(logger, "transport", "HTTP")

		var route = mux.NewRouter()

		route.Handle("/", http.HandlerFunc(MakeVersion(componentName, Version, Environment, GitCommit)))

		//debug
		var debugSubroute = route.PathPrefix("/debug").Subrouter()
		debugSubroute.HandleFunc("/pprof/", http.HandlerFunc(pprof.Index))
		debugSubroute.HandleFunc("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		debugSubroute.HandleFunc("/pprof/profile", http.HandlerFunc(pprof.Profile))
		debugSubroute.HandleFunc("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		debugSubroute.HandleFunc("/pprof/trace", http.HandlerFunc(pprof.Trace))

		//event
		var eventSubroute = route.PathPrefix("/event").Subrouter()
		var eventHandler http.Handler
		{
			eventHandler = event.MakeReceiverHandler(eventsEndpoints.KeycloakEvents, logger)
			eventHandler = event.MakeTracingMiddleware(tracer, "event")(eventHandler)
		}
		eventSubroute.Handle("/receiver", eventHandler)

		//other

		logger.Log("addr", httpAddr)

		errc <- http.ListenAndServe(httpAddr, route)
	}()

	// Influx writing.
	go func() {
		var tic = time.NewTicker(influxWriteInterval)
		defer tic.Stop()
		influxMetrics.WriteLoop(tic.C)
	}()

	// Redis writing.
	if redisEnabled {
		go func() {
			var tic = time.NewTicker(redisWriteInterval)
			defer tic.Stop()
			for range tic.C {
				redisConn.Flush()
			}
		}()
	}

	logger.Log("error", <-errc)
}

type info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Env     string `json:"environment"`
	Commit  string `json:"commit"`
}

// MakeVersion makes a HTTP handler that returns information about the version of the bridge.
func MakeVersion(componentName, version, environment, gitCommit string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		var infos = info{
			Name:    componentName,
			Version: version,
			Env:     environment,
			Commit:  gitCommit,
		}

		var j, err = json.Marshal(infos)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	}
}

func config(logger log.Logger) map[string]interface{} {

	logger.Log("msg", "load configuration and command args")

	// Component default.
	viper.SetDefault("config-file", "./conf/DEV/keycloak_bridge.yml")
	viper.SetDefault("component-name", "keycloak-bridge")
	viper.SetDefault("component-http-address", "0.0.0.0:8888")
	viper.SetDefault("component-grpc-address", "0.0.0.0:5555")

	// Keycloak default.
	viper.SetDefault("keycloak-url", "127.0.0.1:8080")
	viper.SetDefault("keycloak-username", "admin")
	viper.SetDefault("keycloak-password", "admin")
	viper.SetDefault("keycloak-timeout-ms", 5000)

	// Influx DB client default.
	viper.SetDefault("influx", false)
	viper.SetDefault("influx-url", "")
	viper.SetDefault("influx-username", "")
	viper.SetDefault("influx-password", "")
	viper.SetDefault("influx-database", "")
	viper.SetDefault("influx-precision", "")
	viper.SetDefault("influx-retention-policy", "")
	viper.SetDefault("influx-write-consistency", "")
	viper.SetDefault("influx-write-interval-ms", 1000)

	// Sentry client default.
	viper.SetDefault("sentry", false)
	viper.SetDefault("sentry-dsn", "")

	// Jaeger tracing default.
	viper.SetDefault("jaeger", false)
	viper.SetDefault("jaeger-sampler-type", "")
	viper.SetDefault("jaeger-sampler-param", 0)
	viper.SetDefault("jaeger-sampler-url", "")
	viper.SetDefault("jaeger-reporter-logspan", false)
	viper.SetDefault("jaeger-write-interval-ms", 1000)

	// Debug routes enabled.
	viper.SetDefault("pprof-route-enabled", true)

	// Redis.
	viper.SetDefault("redis", false)
	viper.SetDefault("redis-url", "")
	viper.SetDefault("redis-password", "")
	viper.SetDefault("redis-database", 0)
	viper.SetDefault("redis-write-interval-ms", 1000)

	// First level of override.
	pflag.String("config-file", viper.GetString("config-file"), "The configuration file path can be relative or absolute.")
	viper.BindPFlag("config-file", pflag.Lookup("config-file"))
	pflag.Parse()

	// Load and log config.
	viper.SetConfigFile(viper.GetString("config-file"))
	var err = viper.ReadInConfig()
	if err != nil {
		logger.Log("error", err)
	}
	var config = viper.AllSettings()

	// If the URL is not set, we consider the components disabled.
	config["influx"] = config["influx-url"].(string) != ""
	config["sentry"] = config["sentry-dsn"].(string) != ""
	config["jaeger"] = config["jaeger-sampler-url"].(string) != ""
	config["redis"] = config["redis-url"].(string) != ""

	for k, v := range config {
		logger.Log(k, v)
	}

	return config
}
