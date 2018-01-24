package main

import (
	"fmt"
<<<<<<< HEAD
	"io"
=======
>>>>>>> origin/refactor_user
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	keycloak_client "github.com/cloudtrust/keycloak-client/client"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/google/flatbuffers/go"
	"github.com/gorilla/mux"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

<<<<<<< HEAD
	events_components "github.com/cloudtrust/keycloak-bridge/services/events/component"
	events_endpoints "github.com/cloudtrust/keycloak-bridge/services/events/endpoint"
	events_console "github.com/cloudtrust/keycloak-bridge/services/events/module/console"
	events_statistics "github.com/cloudtrust/keycloak-bridge/services/events/module/statistics"
	events_transport_http "github.com/cloudtrust/keycloak-bridge/services/events/transport/http"

	users_components "github.com/cloudtrust/keycloak-bridge/services/users/component"
	users_endpoints "github.com/cloudtrust/keycloak-bridge/services/users/endpoint"
	users_keycloak "github.com/cloudtrust/keycloak-bridge/services/users/module/keycloak"
	users_transport "github.com/cloudtrust/keycloak-bridge/services/users/transport"
	users_flatbuf "github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer/fb"
	sentry "github.com/getsentry/raven-go"
	gokit_influx "github.com/go-kit/kit/metrics/influx"
	influx_client "github.com/influxdata/influxdb/client/v2"
	stdopentracing "github.com/opentracing/opentracing-go"
	jaegerConfig "github.com/uber/jaeger-client-go/config"
=======
	events_components "github.com/cloudtrust/keycloak-bridge/services/events/components"
	events_endpoints "github.com/cloudtrust/keycloak-bridge/services/events/endpoints"
	events_console "github.com/cloudtrust/keycloak-bridge/services/events/modules/console"
	events_statistics "github.com/cloudtrust/keycloak-bridge/services/events/modules/statistics"
	events_transport "github.com/cloudtrust/keycloak-bridge/services/events/transport"

	users_components "github.com/cloudtrust/keycloak-bridge/services/users/components"
	users_endpoints "github.com/cloudtrust/keycloak-bridge/services/users/endpoints"
	users_keycloak "github.com/cloudtrust/keycloak-bridge/services/users/modules/keycloak"
	users_transport "github.com/cloudtrust/keycloak-bridge/services/users/transport"
	users_fb "github.com/cloudtrust/keycloak-bridge/services/users/transport/fb"
	sentry "github.com/getsentry/raven-go"
	gokit_influx "github.com/go-kit/kit/metrics/influx"
	influx_client "github.com/influxdata/influxdb/client/v2"
>>>>>>> origin/refactor_user
)

var (
	// Version of the component.
	Version = "1.0.0"
	// Environment is filled by the compiler.
	Environment = "unknown"
	// GitCommit is filled by the compiler.
	GitCommit = "unknown"
)

<<<<<<< HEAD
=======
type componentConfig struct {
	configFile           string
	ComponentName        string
	ComponentHTTPAddress string
	ComponentGRPCAddress string
	KeycloakURL          string
}

>>>>>>> origin/refactor_user
func main() {

	/*
		Logger
	*/
	var logger = log.NewLogfmtLogger(os.Stdout)
	{
		logger = log.With(logger, "time", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
		defer logger.Log("msg", "Goodbye")
	}

	/*
		Configurations
	*/
	config := config(log.With(logger, "component", "config_loader"))
	var (
		grpcAddr   = fmt.Sprintf(config["component-grpc-address"].(string))
		httpConfig = keycloak_client.HttpConfig{
			Addr:     config["keycloak-url"].(string),
			Username: config["keycloak-username"].(string),
			Password: config["keycloak-password"].(string),
			Timeout:  5 * time.Second,
		}
<<<<<<< HEAD
		influxHTTPConfig = influx_client.HTTPConfig{
=======
		influxHttpConfig = influx_client.HTTPConfig{
>>>>>>> origin/refactor_user
			Addr:     config["influx-url"].(string),
			Username: config["influx-username"].(string),
			Password: config["influx-password"].(string),
		}
		influxBatchPointsConfig = influx_client.BatchPointsConfig{
<<<<<<< HEAD
			Precision:        config["influx-precision"].(string),
			Database:         config["influx-database"].(string),
			RetentionPolicy:  config["influx-retention-policy"].(string),
			WriteConsistency: config["influx-write-consistency"].(string),
		}

		httpAddr            = fmt.Sprintf(config["component-http-address"].(string))
		sentryDSN           = fmt.Sprintf(config["sentry-dsn"].(string))
		jaegerConfiguration = jaegerConfig.Configuration{
			Sampler: &jaegerConfig.SamplerConfig{
				Type:              config["jaeger-sampler-type"].(string),
				Param:             float64(config["jaeger-sampler-param"].(int)),
				SamplingServerURL: config["jaeger-sampler-url"].(string),
			},
			Reporter: &jaegerConfig.ReporterConfig{
				LogSpans:            config["jaeger-reporter-logspan"].(bool),
				BufferFlushInterval: time.Duration(config["jaeger-reporter-flushinterval-ms"].(int)) * time.Millisecond,
			},
		}
		jaegerName = config["jaeger-service-name"].(string)
=======
			Precision:        "s",
			Database:         "keycloak",
			RetentionPolicy:  "",
			WriteConsistency: "",
		}
		httpAddr  = fmt.Sprintf(config["component-http-address"].(string))
		sentryDSN = fmt.Sprintf(config["sentry-dsn"].(string))
>>>>>>> origin/refactor_user
	)

	/*
		Critical errors channel
	*/
	var errc = make(chan error)
	go func() {
		var c = make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	/*
		Create the keycloak client
	*/
	var keycloakClient keycloak_client.Client
	{
		var logger = log.With(logger, "keycloak_config", httpConfig.Addr)
		var err error
		keycloakClient, err = keycloak_client.NewHttpClient(httpConfig)
		if err != nil {
			logger.Log("msg", "Couldn't create Keycloak client", "error", err)
			return
		}
	}

	/*
		Sentry
	*/
	var sentryClient *sentry.Client
	{
		var logger = log.With(logger, "sentry_config", sentryDSN)
		var err error
		sentryClient, err = sentry.New(sentryDSN)
		if err != nil {
			logger.Log("msg", "Couldn't create Sentry client", "error", err)
			return
		}
	}

	//Influx Client instantiation
	var influxClient influx_client.Client
	{
		var logger = log.With(logger, "module", "influx")
		{
			var err error
			influxClient, err = influx_client.NewHTTPClient(influxHTTPConfig)
			if err != nil {
				logger.Log("msg", "Couldn't create Influx client", "error", err)
				return
			}
		}
	}

	//Influx go-kit handler
	var in *gokit_influx.Influx
	{
		in = gokit_influx.New(
			map[string]string{"service": "users"},
			influxBatchPointsConfig,
			log.With(logger, "msg", "go-kit influx"),
		)
	}

	//Tracer
	var tracer stdopentracing.Tracer
	var closer io.Closer
	{
		var err error
		tracer, closer, err = jaegerConfiguration.New(
			jaegerName,
		)
		if err != nil {
			logger.Log("error", err)
		}
	}
	stdopentracing.SetGlobalTracer(tracer)
	defer closer.Close()

	/********
	User stack
	 *********/

	var keycloakModule users_keycloak.Service
	{
		keycloakModule = users_keycloak.NewBasicService(keycloakClient)
	}

	var userComponent users_components.Service
	{
		var logger = log.With(logger)
		userComponent = users_components.NewBasicService(keycloakModule)
		userComponent = users_components.MakeServiceLoggingMiddleware(logger)(userComponent)
	}

	/*
		Endpoint configurations
	*/
	var getUsersEndpoint endpoint.Endpoint
	{
		var logger = log.With(logger, "Method", "GetUsers")
		var innerLogger = log.With(logger, "InnerMethod", "GetUser")
		getUsersEndpoint = users_endpoints.MakeGetUsersEndpoint(
			userComponent,
			users_endpoints.MakeEndpointLoggingMiddleware(innerLogger, "outer_req_id", "inner_req_id"),
<<<<<<< HEAD
			//users_endpoints.MakeEndpointSnowflakeMiddleware("inner_req_id"),
			users_endpoints.MakeEndpointTracingMiddleware(tracer, "getUsers"),
		)
		getUsersEndpoint = users_endpoints.MakeEndpointLoggingMiddleware(logger, "outer_req_id")(getUsersEndpoint)
		getUsersEndpoint = users_endpoints.MakeTSMiddleware(in.NewHistogram("get_users_statistics"))(getUsersEndpoint)
		//getUsersEndpoint = users_endpoints.MakeEndpointSnowflakeMiddleware("outer_req_id")(getUsersEndpoint)
		//getUsersEndpoint = users_endpoints.MakeEndpointTracingMiddleware(tracer, "getUsers")(getUsersEndpoint)
	}

	var usersEndpoints = users_endpoints.Endpoints{
=======
		)
		getUsersEndpoint = users_endpoints.MakeEndpointLoggingMiddleware(logger, "outer_req_id")(getUsersEndpoint)
		getUsersEndpoint = users_endpoints.MakeTSMiddleware(in.NewHistogram("get_users_statistics"))(getUsersEndpoint)
	}

	var users_endpoints = users_endpoints.Endpoints{
>>>>>>> origin/refactor_user
		GetUsersEndpoint: getUsersEndpoint,
	}

	/*
		GRPC server instantiation :
			The above Endpoints is used as a GRPC endpoint directly, shortcutting go-kit's facilities.
	*/
	go func() {
		var userServer = users_transport.NewGrpcServer(usersEndpoints)
		var userGrpcServer = grpc.NewServer(grpc.CustomCodec(flatbuffers.FlatbuffersCodec{}))
		users_fb.RegisterUserServiceServer(userGrpcServer, userServer)
		var lis net.Listener
		{
			var err error
			lis, err = net.Listen("tcp", grpcAddr)
			if err != nil {
				logger.Log("msg", "Couldn't initialize listener", "error", err)
				errc <- err
				return
			}
		}
		errc <- userGrpcServer.Serve(lis)
	}()

<<<<<<< HEAD
	/********
		Event stack
	*********/
=======
	/*
		Event stack
	*/
>>>>>>> origin/refactor_user
	var consoleModule events_console.Service
	{
		var loggerEvent = log.NewJSONLogger(os.Stdout)
		loggerEvent = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
		consoleModule = events_console.NewBasicService(&loggerEvent)
		consoleModule = events_console.MakeServiceLoggingMiddleware(logger)(consoleModule)
	}

	var statisticsModule events_statistics.KeycloakStatisticsProcessor
	{
		statisticsModule = events_statistics.NewKeycloakStatisticsProcessor(influxClient, influxBatchPointsConfig)
	}

	var adminEventComponent events_components.AdminEventService
	{
		var fns = [](func(map[string]string) error){consoleModule.Print, statisticsModule.Stats}
		adminEventComponent = events_components.NewAdminEventService(fns, fns, fns, fns)
		adminEventComponent = events_components.MakeServiceLoggingAdminEventMiddleware(logger)(adminEventComponent)
	}

	var eventComponent events_components.EventService
	{
		var fns = [](func(map[string]string) error){consoleModule.Print, statisticsModule.Stats}
		eventComponent = events_components.NewEventService(fns, fns)
	}

	var muxComponent events_components.MuxService
	{
		muxComponent = events_components.NewMuxService(eventComponent, adminEventComponent)
		muxComponent = events_components.MakeServiceLoggingMuxMiddleware(logger)(muxComponent)
		muxComponent = events_components.MakeServiceErrorMiddleware(logger, sentryClient)(muxComponent)

	}

	var eventConsumerEndpoint endpoint.Endpoint
	{
		eventConsumerEndpoint = events_endpoints.MakeKeycloakEventsEndpoint(muxComponent)
		eventConsumerEndpoint = events_endpoints.MakeEndpointLoggingMiddleware(logger)(eventConsumerEndpoint)
		eventConsumerEndpoint = events_endpoints.MakeEndpointTracingMiddleware(tracer, "events")(eventConsumerEndpoint)
		eventConsumerEndpoint = events_endpoints.MakeCorrelationIDMiddleware()(eventConsumerEndpoint)

<<<<<<< HEAD
	}

	var eventsEndpoints = events_endpoints.Endpoints{
		KeycloakEvents: eventConsumerEndpoint,
	}

=======
	var events_endpoints = events_endpoints.Endpoints{
		MakeKeycloakEventsEndpoint: eventConsumerEndpoint,
	}

>>>>>>> origin/refactor_user
	/*
		HTTP monitoring routes.
	*/
	go func() {
		var logger = log.With(logger, "transport", "HTTP")

		var route = mux.NewRouter()

		route.Handle("/version", http.HandlerFunc(MakeVersion(Version)))

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
			eventHandler = events_transport_http.MakeReceiverHandler(eventsEndpoints.KeycloakEvents, logger)
			eventHandler = events_transport_http.MakeTracingMiddleware(tracer, "event")(eventHandler)
		}
		eventSubroute.Handle("/receiver", eventHandler)

		//other

		logger.Log("addr", httpAddr)

		errc <- http.ListenAndServe(httpAddr, route)
	}()

	//Influx Handling
	go func() {
		var tic = time.NewTicker(10 * time.Second)
		in.WriteLoop(tic.C, influxClient)
	}()

	logger.Log("error", <-errc)
}

func MakeVersion(version string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("Application version : %s\n", version)))
	}
}

func config(logger log.Logger) map[string]interface{} {

	logger.Log("msg", "Loading configuration & command args")
	var configFile = "./conf/DEV/keycloak_bridge.yaml"

	/*
		Component default
	*/
<<<<<<< HEAD
	viper.SetDefault("config-file", configFile)
=======
	viper.SetDefault("config-file", "./conf/DEV/keycloak_bridge.yaml")
>>>>>>> origin/refactor_user
	viper.SetDefault("component-name", "keycloak-bridge")
	viper.SetDefault("component-http-address", "127.0.0.1:8888")
	viper.SetDefault("component-grpc-address", "127.0.0.1:5555")

	// Flaki generator default.
	viper.SetDefault("flaki-node-id", 0)
	viper.SetDefault("flaki-component-id", 0)

	/*
		Keycloak client default
	*/
	viper.SetDefault("keycloak-url", "http://localhost:8080")
	viper.SetDefault("keycloak-username", "admin")
	viper.SetDefault("keycloak-password", "admin")

	/*
		Influx DB client default
	*/
	viper.SetDefault("influx-url", "http://localhost:8086")
	viper.SetDefault("influx-username", "admin")
	viper.SetDefault("influx-password", "admin")
	viper.SetDefault("influx-database", "keycloak")
	viper.SetDefault("influx-precision", "ms")
	viper.SetDefault("influx-retention-policy", "")
	viper.SetDefault("influx-write-consistency", "")

	/*
		Sentry client default
	*/
<<<<<<< HEAD
	viper.SetDefault("sentry-dsn", "https://1b7fa325246a4aa4a4100b72b5a62038:9723f394f672468d9f95a717499cfa86@sentry.io/271870")

	/*
		Jaeger default
	*/
	viper.SetDefault("jaeger-service-name", "keycloak_bridge")
	viper.SetDefault("jaeger-sampler-type", "const")
	viper.SetDefault("jaeger-sampler-param", 1)
	viper.SetDefault("jaeger-sampler-url", "http://127.0.0.1:5775/")
	viper.SetDefault("jaeger-reporter-logspan", false)
	viper.SetDefault("jaeger-reporter-flushinterval-ms", 1000)

	/*
=======
	viper.SetDefault("sentry-dsn", "https://99360b38b8c947baaa222a5367cd74bc:579dc85095114b6198ab0f605d0dc576@sentry-cloudtrust.dev.elca.ch/2")

	/*
>>>>>>> origin/refactor_user
		First level of overhide
	*/
	pflag.String("config-file", viper.GetString("config-file"), "The configuration file path can be relative or absolute.")
	viper.BindPFlag("config-file", pflag.Lookup("config-file"))
	pflag.Parse()

	/*
		Load & log Config
	*/
	viper.SetConfigFile(viper.GetString("config-file"))
	err := viper.ReadInConfig()
	if err != nil {
		logger.Log("msg", err)
	}

	var config = viper.AllSettings()
	for k, v := range config {
		logger.Log(k, v)
	}

	return config
}
