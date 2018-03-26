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
	"sort"
	"syscall"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/user/fb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakd"
	"github.com/cloudtrust/keycloak-bridge/pkg/event"
	fb_flaki "github.com/cloudtrust/keycloak-bridge/pkg/flaki/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware"
	"github.com/cloudtrust/keycloak-bridge/pkg/user"
	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/coreos/go-systemd/dbus"
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
	Version = "1.0"
	// Environment is filled by the compiler.
	Environment = "unknown"
	// GitCommit is filled by the compiler.
	GitCommit = "unknown"
)

func main() {
	// Logger.
	var logger = log.NewJSONLogger(os.Stdout)
	{
		logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	}
	defer logger.Log("msg", "goodbye")

	// Configurations.
	var config = config(log.With(logger, "unit", "config"))
	var (
		// Component
		componentName = config["component-name"].(string)
		grpcAddr      = config["component-grpc-host-port"].(string)
		httpAddr      = config["component-http-host-port"].(string)

		// Flaki
		flakiAddr = config["flaki-host-port"].(string)

		keycloakConfig = keycloak.Config{
			Addr:     fmt.Sprintf("http://%s", config["keycloak-host-port"].(string)),
			Username: config["keycloak-username"].(string),
			Password: config["keycloak-password"].(string),
			Timeout:  time.Duration(config["keycloak-timeout-ms"].(int)) * time.Millisecond,
		}

		// Enabled units
		influxEnabled     = config["influx"].(bool)
		sentryEnabled     = config["sentry"].(bool)
		redisEnabled      = config["redis"].(bool)
		jaegerEnabled     = config["jaeger"].(bool)
		pprofRouteEnabled = config["pprof-route-enabled"].(bool)

		// Influx
		influxHTTPConfig = influx.HTTPConfig{
			Addr:     fmt.Sprintf("http://%s", config["influx-host-port"].(string)),
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

		// Jaeger
		jaegerConfig = jaeger.Configuration{
			Disabled: !jaegerEnabled,
			Sampler: &jaeger.SamplerConfig{
				Type:              config["jaeger-sampler-type"].(string),
				Param:             float64(config["jaeger-sampler-param"].(int)),
				SamplingServerURL: fmt.Sprintf("http://%s", config["jaeger-sampler-host-port"].(string)),
			},
			Reporter: &jaeger.ReporterConfig{
				LogSpans:            config["jaeger-reporter-logspan"].(bool),
				BufferFlushInterval: time.Duration(config["jaeger-write-interval-ms"].(int)) * time.Millisecond,
			},
		}
		jaegerCollectorHealthcheckURL = config["jaeger-collector-healthcheck-host-port"].(string)

		// Sentry
		sentryDSN = fmt.Sprintf(config["sentry-dsn"].(string))

		// Redis
		redisURL           = config["redis-host-port"].(string)
		redisPassword      = config["redis-password"].(string)
		redisDatabase      = config["redis-database"].(int)
		redisWriteInterval = time.Duration(config["redis-write-interval-ms"].(int)) * time.Millisecond
	)

	// Redis.
	type Redis interface {
		Close() error
		Do(commandName string, args ...interface{}) (reply interface{}, err error)
		Send(commandName string, args ...interface{}) error
		Flush() error
	}
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
		logger = log.NewJSONLogger(io.MultiWriter(os.Stdout, keycloakd.NewLogstashRedisWriter(redisConn, componentName)))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	}

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
	var keycloakClient *keycloak.Client
	{
		var err error
		keycloakClient, err = keycloak.New(keycloakConfig)
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
		sentryClient = &keycloakd.NoopSentry{}
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

		influxMetrics = keycloakd.NewMetrics(influxClient, gokitInflux)
	} else {
		influxMetrics = &keycloakd.NoopMetrics{}
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

	// Systemd D-Bus connection.
	var systemDConn *dbus.Conn
	{
		var err error
		systemDConn, err = dbus.New()
		if err != nil {
			logger.Log("msg", "could not create systemd D-Bus connection", "error", err)
			return
		}
	}

	// Flaki.
	var flakiClient fb_flaki.FlakiClient
	{
		// Set up a connection to the flaki-service.
		var conn *grpc.ClientConn
		{
			var err error
			conn, err = grpc.Dial(flakiAddr, grpc.WithInsecure(), grpc.WithCodec(flatbuffers.FlatbuffersCodec{}))
			if err != nil {
				logger.Log("msg", "could not connect to flaki-service", "error", err)
				return
			}
			defer conn.Close()
		}

		flakiClient = fb_flaki.NewFlakiClient(conn)
	}

	// User service.
	var userLogger = log.With(logger, "svc", "user")

	var userModule user.Module
	{
		userModule = user.NewModule(keycloakClient)
		userModule = user.MakeModuleInstrumentingMW(influxMetrics.NewHistogram("user_module"))(userModule)
		userModule = user.MakeModuleLoggingMW(log.With(userLogger, "mw", "module"))(userModule)
		userModule = user.MakeModuleTracingMW(tracer)(userModule)
	}

	var userComponent user.Component
	{
		userComponent = user.NewComponent(userModule)
		userComponent = user.MakeComponentInstrumentingMW(influxMetrics.NewHistogram("user_component"))(userComponent)
		userComponent = user.MakeComponentLoggingMW(log.With(userLogger, "mw", "component"))(userComponent)
		userComponent = user.MakeComponentTracingMW(tracer)(userComponent)
	}

	var userEndpoint endpoint.Endpoint
	{
		userEndpoint = user.MakeGetUsersEndpoint(userComponent)
		userEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("user_endpoint"))(userEndpoint)
		userEndpoint = middleware.MakeEndpointLoggingMW(log.With(userLogger, "mw", "endpoint", "unit", "getusers"))(userEndpoint)
		userEndpoint = middleware.MakeEndpointTracingMW(tracer, "user_endpoint")(userEndpoint)
		userEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(userEndpoint)
	}

	var userEndpoints = user.Endpoints{
		Endpoint: userEndpoint,
	}

	// Event service.
	var eventLogger = log.With(logger, "svc", "event")

	var consoleModule event.ConsoleModule
	{
		consoleModule = event.NewConsoleModule(log.With(eventLogger, "module", "console"))
		consoleModule = event.MakeConsoleModuleInstrumentingMW(influxMetrics.NewHistogram("console_module"))(consoleModule)
		consoleModule = event.MakeConsoleModuleLoggingMW(log.With(eventLogger, "mw", "module", "unit", "console"))(consoleModule)
		consoleModule = event.MakeConsoleModuleTracingMW(tracer)(consoleModule)
	}

	var statisticModule event.StatisticModule
	{
		statisticModule = event.NewStatisticModule(influxMetrics, influxBatchPointsConfig)
		statisticModule = event.MakeStatisticModuleInstrumentingMW(influxMetrics.NewHistogram("statistic_module"))(statisticModule)
		statisticModule = event.MakeStatisticModuleLoggingMW(log.With(eventLogger, "mw", "module", "unit", "statistic"))(statisticModule)
		statisticModule = event.MakeStatisticModuleTracingMW(tracer)(statisticModule)
	}

	var eventAdminComponent event.AdminComponent
	{
		var fns = []event.FuncEvent{consoleModule.Print, statisticModule.Stats}
		eventAdminComponent = event.NewAdminComponent(fns, fns, fns, fns)
		eventAdminComponent = event.MakeAdminComponentInstrumentingMW(influxMetrics.NewHistogram("admin_component"))(eventAdminComponent)
		eventAdminComponent = event.MakeAdminComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "admin_event"))(eventAdminComponent)
		eventAdminComponent = event.MakeAdminComponentTracingMW(tracer)(eventAdminComponent)
	}

	var eventComponent event.Component
	{
		var fns = []event.FuncEvent{consoleModule.Print, statisticModule.Stats}
		eventComponent = event.NewComponent(fns, fns)
		eventComponent = event.MakeComponentInstrumentingMW(influxMetrics.NewHistogram("component"))(eventComponent)
		eventComponent = event.MakeComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "event"))(eventComponent)
		eventComponent = event.MakeComponentTracingMW(tracer)(eventComponent)
	}

	var muxComponent event.MuxComponent
	{
		muxComponent = event.NewMuxComponent(eventComponent, eventAdminComponent)
		muxComponent = event.MakeMuxComponentInstrumentingMW(influxMetrics.NewHistogram("mux_component"))(muxComponent)
		muxComponent = event.MakeMuxComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "mux"))(muxComponent)
		muxComponent = event.MakeMuxComponentTracingMW(tracer)(muxComponent)
	}

	var eventEndpoint endpoint.Endpoint
	{
		eventEndpoint = event.MakeEventEndpoint(muxComponent)
		eventEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("event_endpoint"))(eventEndpoint)
		eventEndpoint = middleware.MakeEndpointLoggingMW(log.With(eventLogger, "mw", "endpoint"))(eventEndpoint)
		eventEndpoint = middleware.MakeEndpointTracingMW(tracer, "event_endpoint")(eventEndpoint)
		eventEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(eventEndpoint)
	}

	var eventEndpoints = event.Endpoints{
		Endpoint: eventEndpoint,
	}

	// Health service.
	var healthLogger = log.With(logger, "svc", "health")

	var healthComponent health.Component
	{
		var influxHM = health.NewInfluxModule(influxMetrics, influxEnabled)
		var jaegerHM = health.NewJaegerModule(systemDConn, http.DefaultClient, jaegerCollectorHealthcheckURL, jaegerEnabled)
		var redisHM = health.NewRedisModule(redisConn, redisEnabled)
		var sentryHM = health.NewSentryModule(sentryClient, http.DefaultClient, sentryEnabled)
		var keycloakHM, err = health.NewKeycloakModule(keycloakClient, Version)
		if err != nil {
			logger.Log("msg", "could not create keycloak health check module", "error", err)
			return
		}

		healthComponent = health.NewComponent(influxHM, jaegerHM, redisHM, sentryHM, keycloakHM)
	}

	var influxHealthEndpoint endpoint.Endpoint
	{
		influxHealthEndpoint = health.MakeInfluxHealthCheckEndpoint(healthComponent)
		influxHealthEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("influx_health_endpoint"))(influxHealthEndpoint)
		influxHealthEndpoint = middleware.MakeEndpointLoggingMW(log.With(healthLogger, "mw", "endpoint", "unit", "influx"))(influxHealthEndpoint)
		influxHealthEndpoint = middleware.MakeEndpointTracingMW(tracer, "influx_health_endpoint")(influxHealthEndpoint)
		influxHealthEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(influxHealthEndpoint)
	}
	var jaegerHealthEndpoint endpoint.Endpoint
	{
		jaegerHealthEndpoint = health.MakeJaegerHealthCheckEndpoint(healthComponent)
		jaegerHealthEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("jaeger_health_endpoint"))(jaegerHealthEndpoint)
		jaegerHealthEndpoint = middleware.MakeEndpointLoggingMW(log.With(healthLogger, "mw", "endpoint", "unit", "jaeger"))(jaegerHealthEndpoint)
		jaegerHealthEndpoint = middleware.MakeEndpointTracingMW(tracer, "jaeger_health_endpoint")(jaegerHealthEndpoint)
		jaegerHealthEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(jaegerHealthEndpoint)
	}
	var redisHealthEndpoint endpoint.Endpoint
	{
		redisHealthEndpoint = health.MakeRedisHealthCheckEndpoint(healthComponent)
		redisHealthEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("redis_health_endpoint"))(redisHealthEndpoint)
		redisHealthEndpoint = middleware.MakeEndpointLoggingMW(log.With(healthLogger, "mw", "endpoint", "unit", "redis"))(redisHealthEndpoint)
		redisHealthEndpoint = middleware.MakeEndpointTracingMW(tracer, "redis_health_endpoint")(redisHealthEndpoint)
		redisHealthEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(redisHealthEndpoint)
	}
	var sentryHealthEndpoint endpoint.Endpoint
	{
		sentryHealthEndpoint = health.MakeSentryHealthCheckEndpoint(healthComponent)
		sentryHealthEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("sentry_health_endpoint"))(sentryHealthEndpoint)
		sentryHealthEndpoint = middleware.MakeEndpointLoggingMW(log.With(healthLogger, "mw", "endpoint", "unit", "sentry"))(sentryHealthEndpoint)
		sentryHealthEndpoint = middleware.MakeEndpointTracingMW(tracer, "sentry_health_endpoint")(sentryHealthEndpoint)
		sentryHealthEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(sentryHealthEndpoint)
	}

	var keycloakHealthEndpoint endpoint.Endpoint
	{
		keycloakHealthEndpoint = health.MakeKeycloakHealthCheckEndpoint(healthComponent)
		keycloakHealthEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("keycloak_health_endpoint"))(keycloakHealthEndpoint)
		keycloakHealthEndpoint = middleware.MakeEndpointLoggingMW(log.With(healthLogger, "mw", "endpoint", "unit", "keycloak"))(keycloakHealthEndpoint)
		keycloakHealthEndpoint = middleware.MakeEndpointTracingMW(tracer, "keycloak_health_endpoint")(keycloakHealthEndpoint)
		keycloakHealthEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(keycloakHealthEndpoint)
	}

	var allHealthEndpoint endpoint.Endpoint
	{
		allHealthEndpoint = health.MakeAllHealthChecksEndpoint(healthComponent)
		allHealthEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("allchecks_health_endpoint"))(allHealthEndpoint)
		allHealthEndpoint = middleware.MakeEndpointLoggingMW(log.With(healthLogger, "mw", "endpoint", "unit", "AllHealthCheck"))(allHealthEndpoint)
		allHealthEndpoint = middleware.MakeEndpointTracingMW(tracer, "allchecks_health_endpoint")(allHealthEndpoint)
		allHealthEndpoint = middleware.MakeEndpointCorrelationIDMW(flakiClient, tracer)(allHealthEndpoint)
	}

	var healthEndpoints = health.Endpoints{
		InfluxHealthCheck:   influxHealthEndpoint,
		JaegerHealthCheck:   jaegerHealthEndpoint,
		RedisHealthCheck:    redisHealthEndpoint,
		SentryHealthCheck:   sentryHealthEndpoint,
		KeycloakHealthCheck: keycloakHealthEndpoint,
		AllHealthChecks:     allHealthEndpoint,
	}

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

		// User Handler.
		var getUsersHandler grpc_transport.Handler
		{
			getUsersHandler = user.MakeGRPCGetUsersHandler(userEndpoints.Endpoint)
			getUsersHandler = middleware.MakeGRPCTracingMW(tracer, componentName, "grpc_server_getusers")(getUsersHandler)
		}

		var grpcServer = user.NewGRPCServer(getUsersHandler)
		var userServer = grpc.NewServer(grpc.CustomCodec(flatbuffers.FlatbuffersCodec{}))
		fb.RegisterUserServiceServer(userServer, grpcServer)

		errc <- userServer.Serve(lis)
	}()

	// HTTP Server.
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Log("addr", httpAddr)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", http.HandlerFunc(MakeVersion(componentName, Version, Environment, GitCommit)))

		// Event.
		var eventSubroute = route.PathPrefix("/event").Subrouter()

		var eventHandler http.Handler
		{
			eventHandler = event.MakeHTTPEventHandler(eventEndpoints.Endpoint)
			eventHandler = middleware.MakeHTTPTracingMW(tracer, componentName, "http_server_event")(eventHandler)
		}
		eventSubroute.Handle("/receiver", eventHandler)

		// Users.
		var getUsersHandler http.Handler
		{
			getUsersHandler = user.MakeHTTPGetUsersHandler(userEndpoints.Endpoint)
			getUsersHandler = middleware.MakeHTTPTracingMW(tracer, componentName, "http_server_getusers")(getUsersHandler)
		}
		route.Handle("/getusers", getUsersHandler)

		// Health checks.
		var healthSubroute = route.PathPrefix("/health").Subrouter()

		var allHealthChecksHandler = health.MakeAllHealthChecksHandler(healthEndpoints.AllHealthChecks)
		healthSubroute.Handle("", allHealthChecksHandler)

		var influxHealthCheckHandler = health.MakeInfluxHealthCheckHandler(healthEndpoints.InfluxHealthCheck)
		healthSubroute.Handle("/influx", influxHealthCheckHandler)

		var jaegerHealthCheckHandler = health.MakeJaegerHealthCheckHandler(healthEndpoints.JaegerHealthCheck)
		healthSubroute.Handle("/jaeger", jaegerHealthCheckHandler)

		var redisHealthCheckHandler = health.MakeRedisHealthCheckHandler(healthEndpoints.RedisHealthCheck)
		healthSubroute.Handle("/redis", redisHealthCheckHandler)

		var sentryHealthCheckHandler = health.MakeSentryHealthCheckHandler(healthEndpoints.SentryHealthCheck)
		healthSubroute.Handle("/sentry", sentryHealthCheckHandler)

		var keycloakHealthCheckHandler = health.MakeKeycloakHealthCheckHandler(healthEndpoints.KeycloakHealthCheck)
		healthSubroute.Handle("/keycloak", keycloakHealthCheckHandler)

		// Debug.
		if pprofRouteEnabled {
			var debugSubroute = route.PathPrefix("/debug").Subrouter()
			debugSubroute.HandleFunc("/pprof/", http.HandlerFunc(pprof.Index))
			debugSubroute.HandleFunc("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
			debugSubroute.HandleFunc("/pprof/profile", http.HandlerFunc(pprof.Profile))
			debugSubroute.HandleFunc("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
			debugSubroute.HandleFunc("/pprof/trace", http.HandlerFunc(pprof.Trace))
		}

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

		var j, err = json.MarshalIndent(infos, "", "  ")
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
	viper.SetDefault("config-file", "./configs/keycloakd.yml")
	viper.SetDefault("component-name", "keycloak-bridge")
	viper.SetDefault("component-http-host-port", "0.0.0.0:8888")
	viper.SetDefault("component-grpc-host-port", "0.0.0.0:5555")

	// Flaki default.
	viper.SetDefault("flaki-host-port", "")

	// Keycloak default.
	viper.SetDefault("keycloak-host-port", "127.0.0.1:8080")
	viper.SetDefault("keycloak-username", "")
	viper.SetDefault("keycloak-password", "")
	viper.SetDefault("keycloak-timeout-ms", 5000)

	// Influx DB client default.
	viper.SetDefault("influx", false)
	viper.SetDefault("influx-host-port", "")
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
	viper.SetDefault("jaeger-sampler-host-port", "")
	viper.SetDefault("jaeger-reporter-logspan", false)
	viper.SetDefault("jaeger-write-interval-ms", 1000)
	viper.SetDefault("jaeger-collector-healthcheck-host-port", "")

	// Debug routes enabled.
	viper.SetDefault("pprof-route-enabled", true)

	// Redis.
	viper.SetDefault("redis", false)
	viper.SetDefault("redis-host-port", "")
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

	// If the host/port is not set, we consider the components deactivated.
	config["influx"] = config["influx-host-port"].(string) != ""
	config["sentry"] = config["sentry-dsn"].(string) != ""
	config["jaeger"] = config["jaeger-sampler-host-port"].(string) != ""
	config["redis"] = config["redis-host-port"].(string) != ""

	// Log config in alphabetical order.
	var keys []string
	for k := range config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		logger.Log(k, config[k])
	}

	return config
}
