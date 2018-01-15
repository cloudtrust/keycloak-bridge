package main

import (
	"fmt"
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

	events_components "github.com/cloudtrust/keycloak-bridge/services/events/components"
	events_endpoints "github.com/cloudtrust/keycloak-bridge/services/events/endpoints"
	events_console "github.com/cloudtrust/keycloak-bridge/services/events/modules/console"
	events_statistics "github.com/cloudtrust/keycloak-bridge/services/events/modules/statistics"
	events_transport "github.com/cloudtrust/keycloak-bridge/services/events/transport"

	users_components "github.com/cloudtrust/keycloak-bridge/services/users/components"
	users_endpoints "github.com/cloudtrust/keycloak-bridge/services/users/endpoints"
	users_keycloak "github.com/cloudtrust/keycloak-bridge/services/users/modules/keycloak"
	users_transport "github.com/cloudtrust/keycloak-bridge/services/users/transport"
	users_flatbuf "github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer"
	sentry "github.com/getsentry/raven-go"
	gokit_influx "github.com/go-kit/kit/metrics/influx"
	influx_client "github.com/influxdata/influxdb/client/v2"
)

var (
	VERSION = "123"
)

type componentConfig struct {
	configFile           string
	ComponentName        string
	ComponentHTTPAddress string
	ComponentGRPCAddress string
	KeycloakURL          string
}

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
		influxHTTPConfig = influx_client.HTTPConfig{
			Addr:     config["influx-url"].(string),
			Username: config["influx-username"].(string),
			Password: config["influx-password"].(string),
		}
		influxBatchPointsConfig = influx_client.BatchPointsConfig{
			Precision:        "s",
			Database:         "keycloak",
			RetentionPolicy:  "",
			WriteConsistency: "",
		}
		httpAddr  = fmt.Sprintf(config["component-http-address"].(string))
		sentryDSN = fmt.Sprintf(config["sentry-dsn"].(string))
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
		var logger = log.With(logger, "Keycloak Config", httpConfig.Addr)
		var err error
		keycloakClient, err = keycloak_client.NewHttpClient(httpConfig)
		if err != nil {
			logger.Log("Couldn't create Keycloak client", err)
			return
		}
	}

	/*
		Sentry
	*/
	var sentryClient *sentry.Client
	{
		var logger = log.With(logger, "sentry config", sentryDSN)
		var err error
		sentryClient, err = sentry.New(sentryDSN)
		if err != nil {
			logger.Log("Couldn't create Sentry client", err)
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
				logger.Log("Couldn't create Influx client", err)
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
			users_endpoints.MakeEndpointSnowflakeMiddleware("inner_req_id"),
		)
		getUsersEndpoint = users_endpoints.MakeEndpointLoggingMiddleware(logger, "outer_req_id")(getUsersEndpoint)
		getUsersEndpoint = users_endpoints.MakeTSMiddleware(in.NewHistogram("get_users_statistics"))(getUsersEndpoint)
		getUsersEndpoint = users_endpoints.MakeEndpointSnowflakeMiddleware("outer_req_id")(getUsersEndpoint)
	}

	var users_endpoints = users_endpoints.Endpoints{
		GetUsersEndpoint: getUsersEndpoint,
	}

	/*
		GRPC server instantiation :
			The above Endpoints is used as a GRPC endpoint directly, shortcutting go-kit's facilities.
	*/
	go func() {
		var userServer = users_transport.NewGrpcServer(users_endpoints)
		var userGrpcServer = grpc.NewServer(grpc.CustomCodec(flatbuffers.FlatbuffersCodec{}))
		users_flatbuf.RegisterUserServiceServer(userGrpcServer, userServer)
		var lis net.Listener
		{
			var err error
			lis, err = net.Listen("tcp", grpcAddr)
			if err != nil {
				logger.Log("Couldn't initialize listener", err)
				errc <- err
				return
			}
		}
		errc <- userGrpcServer.Serve(lis)
	}()

	/*
		Event stack
	*/
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
	}

	var eventsEndpoints = events_endpoints.Endpoints{
		KeycloakEvents: eventConsumerEndpoint,
	}

	/*
		HTTP monitoring routes.
	*/
	go func() {
		var logger = log.With(logger, "transport", "HTTP")

		var route = mux.NewRouter()

		route.Handle("/version", http.HandlerFunc(MakeVersion(VERSION)))

		//debug
		var debugSubroute = route.PathPrefix("/debug").Subrouter()
		debugSubroute.HandleFunc("/pprof/", http.HandlerFunc(pprof.Index))
		debugSubroute.HandleFunc("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		debugSubroute.HandleFunc("/pprof/profile", http.HandlerFunc(pprof.Profile))
		debugSubroute.HandleFunc("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		debugSubroute.HandleFunc("/pprof/trace", http.HandlerFunc(pprof.Trace))

		//event
		var eventSubroute = route.PathPrefix("/event").Subrouter()
		eventSubroute.Handle("/receiver", events_transport.MakeReceiverHandler(eventsEndpoints.KeycloakEvents, logger))

		//other

		logger.Log("addr", httpAddr)

		errc <- http.ListenAndServe(httpAddr, route)
	}()

	//Influx Handling
	go func() {
		var tic = time.NewTicker(1 * time.Second)
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

	/*
		Component default
	*/
	viper.SetDefault("config-file", "./conf/DEV/keycloak_bridge.yaml")
	viper.SetDefault("component-name", "keycloak-bridge")
	viper.SetDefault("component-http-address", "127.0.0.1:8888")
	viper.SetDefault("component-grpc-address", "127.0.0.1:5555")

	/*
		Keycloak client default
	*/
	viper.SetDefault("keycloak-url", "http://localhost:8080")
	viper.SetDefault("keycloak-username", "admin")
	viper.SetDefault("keycloak-password", "admin")

	/*
		Influx DB client default
	*/
	viper.SetDefault("influx-url", "http://localhost:8080")
	viper.SetDefault("influx-username", "admin")
	viper.SetDefault("influx-password", "admin")

	/*
		Sentry client default
	*/
	viper.SetDefault("sentry-dsn", "https://99360b38b8c947baaa222a5367cd74bc:579dc85095114b6198ab0f605d0dc576@sentry-cloudtrust.dev.elca.ch/2")

	/*
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
		logger.Log(k, v.(string))
	}

	return config
}
