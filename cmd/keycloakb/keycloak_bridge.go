package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/security"

	"github.com/cloudtrust/keycloak-bridge/internal/idgenerator"
	gen "github.com/cloudtrust/keycloak-bridge/internal/idgenerator"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/event"
	"github.com/cloudtrust/keycloak-bridge/pkg/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/export"
	"github.com/cloudtrust/keycloak-bridge/pkg/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware"
	keycloak "github.com/cloudtrust/keycloak-client"
	sentry "github.com/getsentry/raven-go"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	gokit_influx "github.com/go-kit/kit/metrics/influx"
	"github.com/go-kit/kit/ratelimit"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	influx "github.com/influxdata/influxdb/client/v2"
	_ "github.com/lib/pq"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/rs/cors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	jaeger "github.com/uber/jaeger-client-go/config"
	"golang.org/x/time/rate"
)

var (
	// ComponentName is the name of the component.
	ComponentName = "keycloak-bridge"
	// ComponentID is an unique ID generated at component startup.
	ComponentID = "unknown"
	// Version of the component.
	Version = "1.1"
	// Environment is filled by the compiler.
	Environment = "unknown"
	// GitCommit is filled by the compiler.
	GitCommit = "unknown"
)

// Influx client.
type Metrics interface {
	NewCounter(name string) metrics.Counter
	NewGauge(name string) metrics.Gauge
	NewHistogram(name string) metrics.Histogram
	WriteLoop(c <-chan time.Time)
	Write(bp influx.BatchPoints) error
	Ping(timeout time.Duration) (time.Duration, string, error)
}

type dbConfig struct {
	HostPort        string
	Username        string
	Password        string
	Database        string
	Protocol        string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime int
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	ComponentID = strconv.FormatUint(rand.Uint64(), 10)

	// Logger.
	var logger = log.NewJSONLogger(os.Stdout)
	{
		// Timestamp
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)

		// Caller
		logger = log.With(logger, "caller", log.DefaultCaller)

		// Add component name, component ID and version to the logger tags.
		logger = log.With(logger, "component_name", ComponentName, "component_id", ComponentID, "component_version", Version)
	}
	defer logger.Log("msg", "Shutdown")

	// Log component version infos.
	logger.Log("msg", "Starting")
	logger.Log("environment", Environment, "git_commit", GitCommit)

	// Configurations.
	var c = config(log.With(logger, "unit", "config"))
	var (
		// Component
		authorizationConfigFile = c.GetString("authorization-file")

		// Publishing
		httpAddrInternal = c.GetString("http-host-port-internal")
		httpAddrManagement = c.GetString("http-host-port-management")
		httpAddrAccount = c.GetString("http-host-port-account")

		// Keycloak
		keycloakConfig = keycloak.Config{
			AddrTokenProvider: c.GetString("keycloak-oidc-uri"),
			AddrAPI:           c.GetString("keycloak-api-uri"),
			Timeout:           c.GetDuration("keycloak-timeout"),
		}

		// Enabled units
		eventsDBEnabled   = c.GetBool("events-db")
		configDBEnabled   = c.GetBool("config-db")
		influxEnabled     = c.GetBool("influx")
		jaegerEnabled     = c.GetBool("jaeger")
		sentryEnabled     = c.GetBool("sentry")
		pprofRouteEnabled = c.GetBool("pprof-route-enabled")

		// Influx
		influxHTTPConfig = influx.HTTPConfig{
			Addr:     fmt.Sprintf("http://%s", c.GetString("influx-host-port")),
			Username: c.GetString("influx-username"),
			Password: c.GetString("influx-password"),
		}
		influxBatchPointsConfig = influx.BatchPointsConfig{
			Precision:        c.GetString("influx-precision"),
			Database:         c.GetString("influx-database"),
			RetentionPolicy:  c.GetString("influx-retention-policy"),
			WriteConsistency: c.GetString("influx-write-consistency"),
		}
		influxWriteInterval = c.GetDuration("influx-write-interval")

		// Jaeger
		jaegerConfig = jaeger.Configuration{
			Disabled: !jaegerEnabled,
			Sampler: &jaeger.SamplerConfig{
				Type:              c.GetString("jaeger-sampler-type"),
				Param:             c.GetFloat64("jaeger-sampler-param"),
				SamplingServerURL: fmt.Sprintf("http://%s", c.GetString("jaeger-sampler-host-port")),
			},
			Reporter: &jaeger.ReporterConfig{
				LogSpans:            c.GetBool("jaeger-reporter-logspan"),
				BufferFlushInterval: c.GetDuration("jaeger-write-interval"),
			},
		}

		// Sentry
		sentryDSN = c.GetString("sentry-dsn")

		// DB - for the moment used just for audit events
		auditRwDbParams = getDbConfig(c, "db-audit-rw")

		// DB - Read only user for audit events
		auditRoDbParams = getDbConfig(c, "db-audit-ro")

		// DB for custom configuration
		configDbParams = getDbConfig(c, "db-config")

		// Rate limiting
		rateLimit = map[string]int{
			"event":      c.GetInt("rate-event"),
			"management": c.GetInt("rate-management"),
		}

		corsOptions = cors.Options{
			AllowedOrigins:   c.GetStringSlice("cors-allowed-origins"),
			AllowedMethods:   c.GetStringSlice("cors-allowed-methods"),
			AllowCredentials: c.GetBool("cors-allow-credential"),
			AllowedHeaders:   c.GetStringSlice("cors-allowed-headers"),
			Debug:            c.GetBool("cors-debug"),
		}
	)

	// Unique ID generator
	var idGenerator = idgenerator.New(ComponentName, ComponentID)

	// Critical errors channel.
	var errc = make(chan error)
	go func() {
		var c = make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	// Security - Audience required
	var audienceRequired string
	{
		audienceRequired = c.GetString("audience-required")

		if audienceRequired == "" {
			logger.Log("msg", "audience parameter(audience-required) cannot be empty")
			return
		}
	}

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

	// Authorization Manager
	var authorizationManager security.AuthorizationManager
	{
		json, err := ioutil.ReadFile(authorizationConfigFile)

		if err != nil {
			logger.Log("msg", "could not read JSON authorization file", "error", err)
			return
		}

		authorizationManager, err = security.NewAuthorizationManager(keycloakClient, string(json))

		if err != nil {
			logger.Log("msg", "could not load authorizations", "error", err)
			return
		}
	}

	// Sentry.
	type Sentry interface {
		CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
		URL() string
		Close()
	}

	var sentryClient Sentry = &keycloakb.NoopSentry{}
	if sentryEnabled {
		var logger = log.With(logger, "unit", "sentry")
		var err error
		sentryClient, err = sentry.New(sentryDSN)
		if err != nil {
			logger.Log("msg", "could not create Sentry client", "error", err)
			return
		}
		defer sentryClient.Close()
	}

	var influxMetrics Metrics = &keycloakb.NoopMetrics{}
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

		influxMetrics = keycloakb.NewMetrics(influxClient, gokitInflux)
	}

	// Jaeger client.
	var tracer opentracing.Tracer
	{
		var logger = log.With(logger, "unit", "jaeger")
		var closer io.Closer
		var err error

		tracer, closer, err = jaegerConfig.New(ComponentName)
		if err != nil {
			logger.Log("msg", "could not create Jaeger tracer", "error", err)
			return
		}
		defer closer.Close()
	}

	// Audit events DB.
	type CloudtrustDB interface {
		Exec(query string, args ...interface{}) (sql.Result, error)
		Query(query string, args ...interface{}) (*sql.Rows, error)
		QueryRow(query string, args ...interface{}) *sql.Row
		SetMaxOpenConns(n int)
		SetMaxIdleConns(n int)
		SetConnMaxLifetime(d time.Duration)
	}

	var eventsDBConn CloudtrustDB = keycloakb.NoopDB{}
	if eventsDBEnabled {
		var err error
		eventsDBConn, err = auditRwDbParams.openDatabase()
		if err != nil {
			logger.Log("msg", "could not create R/W DB connection for audit events", "error", err)
			return
		}
	}

	var eventsRODBConn events.DBEvents
	{
		var err error
		eventsRODBConn, err = auditRoDbParams.openDatabase()
		if err != nil {
			logger.Log("msg", "could not create RO DB connection for audit events", "error", err)
			return
		}
	}

	var configurationDBConn CloudtrustDB = keycloakb.NoopDB{}
	if configDBEnabled {
		var err error
		configurationDBConn, err = configDbParams.openDatabase()
		if err != nil {
			logger.Log("msg", "could not create DB connection for configuration storage", "error", err)
			return
		}
	}

	// Event service.
	var eventEndpoints = event.Endpoints{}
	{
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

		// new module for sending the events to the DB
		var eventsDBModule event.EventsDBModule
		{
			eventsDBModule = event.NewEventsDBModule(eventsDBConn)
			eventsDBModule = event.MakeEventsDBModuleInstrumentingMW(influxMetrics.NewHistogram("eventsDB_module"))(eventsDBModule)
			eventsDBModule = event.MakeEventsDBModuleLoggingMW(log.With(eventLogger, "mw", "module", "unit", "eventsDB"))(eventsDBModule)
			eventsDBModule = event.MakeEventsDBModuleTracingMW(tracer)(eventsDBModule)
		}

		var eventAdminComponent event.AdminComponent
		{
			var fns = []event.FuncEvent{consoleModule.Print, statisticModule.Stats, eventsDBModule.Store}
			eventAdminComponent = event.NewAdminComponent(fns, fns, fns, fns)
			eventAdminComponent = event.MakeAdminComponentInstrumentingMW(influxMetrics.NewHistogram("admin_component"))(eventAdminComponent)
			eventAdminComponent = event.MakeAdminComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "admin_event"))(eventAdminComponent)
			eventAdminComponent = event.MakeAdminComponentTracingMW(tracer)(eventAdminComponent)
		}

		var eventComponent event.Component
		{
			var fns = []event.FuncEvent{consoleModule.Print, statisticModule.Stats, eventsDBModule.Store}
			eventComponent = event.NewComponent(fns, fns)
			eventComponent = event.MakeComponentInstrumentingMW(influxMetrics.NewHistogram("component"))(eventComponent)
			eventComponent = event.MakeComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "event"))(eventComponent)
			eventComponent = event.MakeComponentTracingMW(tracer)(eventComponent)
		}

		// add ct_type

		var muxComponent event.MuxComponent
		{
			muxComponent = event.NewMuxComponent(eventComponent, eventAdminComponent)
			muxComponent = event.MakeMuxComponentInstrumentingMW(influxMetrics.NewHistogram("mux_component"))(muxComponent)
			muxComponent = event.MakeMuxComponentLoggingMW(log.With(eventLogger, "mw", "component", "unit", "mux"))(muxComponent)
			muxComponent = event.MakeMuxComponentTracingMW(tracer)(muxComponent)
			muxComponent = event.MakeMuxComponentTrackingMW(sentryClient, log.With(eventLogger, "mw", "component"))(muxComponent)
		}

		var eventEndpoint endpoint.Endpoint
		{
			eventEndpoint = event.MakeEventEndpoint(muxComponent)
			eventEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("event_endpoint"))(eventEndpoint)
			eventEndpoint = middleware.MakeEndpointLoggingMW(log.With(eventLogger, "mw", "endpoint"))(eventEndpoint)
			eventEndpoint = middleware.MakeEndpointTracingMW(tracer, "event_endpoint")(eventEndpoint)
		}

		// Rate limiting
		eventEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["event"]))(eventEndpoint)

		eventEndpoints = event.Endpoints{
			Endpoint: eventEndpoint,
		}
	}

	// Events service.
	var eventsEndpoints events.Endpoints
	{
		var eventsLogger = log.With(logger, "svc", "events")

		// new module for sending the events to the DB
		eventsRODBModule := events.NewEventsDBModule(eventsRODBConn)
		eventsComponent := events.NewEventsComponent(eventsRODBModule)
		eventsComponent = events.MakeAuthorizationManagementComponentMW(log.With(eventsLogger, "mw", "endpoint"), authorizationManager)(eventsComponent)

		eventsEndpoints = events.Endpoints{
			GetEvents:        prepareEndpoint(events.MakeGetEventsEndpoint(eventsComponent), "get_events", influxMetrics, eventsLogger, tracer, rateLimit),
			GetEventsSummary: prepareEndpoint(events.MakeGetEventsSummaryEndpoint(eventsComponent), "get_events_summary", influxMetrics, eventsLogger, tracer, rateLimit),
			GetUserEvents:    prepareEndpoint(events.MakeGetEventsEndpoint(eventsComponent), "get_user_events", influxMetrics, eventsLogger, tracer, rateLimit),
		}
	}

	baseEventsDBModule := event.NewEventsDBModule(eventsDBConn)

	// Management service.
	var managementEndpoints = management.Endpoints{}
	{
		var managementLogger = log.With(logger, "svc", "management")

		// module to store API calls of the back office to the DB
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, managementLogger, tracer)

		// module for storing and retrieving the custom configuration
		var configDBModule management.ConfigurationDBModule
		{
			configDBModule = management.NewConfigurationDBModule(configurationDBConn)
			configDBModule = management.MakeConfigurationDBModuleInstrumentingMW(influxMetrics.NewHistogram("configDB_module"))(configDBModule)
			configDBModule = management.MakeConfigurationDBModuleLoggingMW(log.With(managementLogger, "mw", "module", "unit", "configDB"))(configDBModule)
			configDBModule = management.MakeConfigurationDBModuleTracingMW(tracer)(configDBModule)
		}

		var keycloakComponent management.Component
		{
			keycloakComponent = management.NewComponent(keycloakClient, eventsDBModule, configDBModule)
			keycloakComponent = management.MakeAuthorizationManagementComponentMW(log.With(managementLogger, "mw", "endpoint"), authorizationManager)(keycloakComponent)
		}

		managementEndpoints = management.Endpoints{
			GetRealms:                      prepareEndpoint(management.MakeGetRealmsEndpoint(keycloakComponent), "realms_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetRealm:                       prepareEndpoint(management.MakeGetRealmEndpoint(keycloakComponent), "realm_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetClients:                     prepareEndpoint(management.MakeGetClientsEndpoint(keycloakComponent), "get_clients_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetClient:                      prepareEndpoint(management.MakeGetClientEndpoint(keycloakComponent), "get_client_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			CreateUser:                     prepareEndpoint(management.MakeCreateUserEndpoint(keycloakComponent), "create_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetUser:                        prepareEndpoint(management.MakeGetUserEndpoint(keycloakComponent), "get_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			UpdateUser:                     prepareEndpoint(management.MakeUpdateUserEndpoint(keycloakComponent), "update_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			DeleteUser:                     prepareEndpoint(management.MakeDeleteUserEndpoint(keycloakComponent), "delete_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetUsers:                       prepareEndpoint(management.MakeGetUsersEndpoint(keycloakComponent), "get_users_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetUserAccountStatus:           prepareEndpoint(management.MakeGetUserAccountStatusEndpoint(keycloakComponent), "get_user_accountstatus", influxMetrics, managementLogger, tracer, rateLimit),
			GetRoles:                       prepareEndpoint(management.MakeGetRolesEndpoint(keycloakComponent), "get_roles_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetRole:                        prepareEndpoint(management.MakeGetRoleEndpoint(keycloakComponent), "get_role_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetClientRoles:                 prepareEndpoint(management.MakeGetClientRolesEndpoint(keycloakComponent), "get_client_roles_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			CreateClientRole:               prepareEndpoint(management.MakeCreateClientRoleEndpoint(keycloakComponent), "create_client_role_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetClientRoleForUser:           prepareEndpoint(management.MakeGetClientRolesForUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			AddClientRoleToUser:            prepareEndpoint(management.MakeAddClientRolesToUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetRealmRoleForUser:            prepareEndpoint(management.MakeGetRealmRolesForUserEndpoint(keycloakComponent), "get_realm_roles_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			ResetPassword:                  prepareEndpoint(management.MakeResetPasswordEndpoint(keycloakComponent), "reset_password_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			SendVerifyEmail:                prepareEndpoint(management.MakeSendVerifyEmailEndpoint(keycloakComponent), "send_verify_email_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			ExecuteActionsEmail:            prepareEndpoint(management.MakeExecuteActionsEmailEndpoint(keycloakComponent), "execute_actions_email_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			SendNewEnrolmentCode:           prepareEndpoint(management.MakeSendNewEnrolmentCodeEndpoint(keycloakComponent), "send_new_enrolment_code_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetCredentialsForUser:          prepareEndpoint(management.MakeGetCredentialsForUserEndpoint(keycloakComponent), "get_credentials_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			DeleteCredentialsForUser:       prepareEndpoint(management.MakeDeleteCredentialsForUserEndpoint(keycloakComponent), "delete_credentials_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			GetRealmCustomConfiguration:    prepareEndpoint(management.MakeGetRealmCustomConfigurationEndpoint(keycloakComponent), "get_realm_custom_config_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
			UpdateRealmCustomConfiguration: prepareEndpoint(management.MakeUpdateRealmCustomConfigurationEndpoint(keycloakComponent), "update_realm_custom_config_endpoint", influxMetrics, managementLogger, tracer, rateLimit),
		}
	}

	// Account service.
	var accountEndpoints account.Endpoints
	{
		var accountLogger = log.With(logger, "svc", "account")

		// Configure events db module
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, accountLogger, tracer)

		// new module for account service
		accountComponent := account.NewComponent(keycloakClient, eventsDBModule)

		accountEndpoints = account.Endpoints{
			UpdatePassword: prepareEndpoint(account.MakeUpdatePasswordEndpoint(accountComponent), "update_password", influxMetrics, accountLogger, tracer, rateLimit),
		}
	}

	// Export configuration
	var exportModule = export.NewModule(keycloakClient)
	var cfgStorageModue = export.NewConfigStorageModule(eventsDBConn)

	var exportComponent = export.NewComponent(ComponentName, Version, exportModule, cfgStorageModue)
	var exportEndpoint = export.MakeExportEndpoint(exportComponent)
	var exportSaveAndExportEndpoint = export.MakeStoreAndExportEndpoint(exportComponent)

	// HTTP Internal Call Server (Event reception from Keycloak & Export API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Log("addr", httpAddrInternal)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", http.HandlerFunc(makeVersion(ComponentName, ComponentID, Version, Environment, GitCommit)))

		// Event.
		var eventSubroute = route.PathPrefix("/event").Subrouter()

		var eventHandler http.Handler
		{
			eventHandler = event.MakeHTTPEventHandler(eventEndpoints.Endpoint)
			eventHandler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(eventHandler)
			eventHandler = middleware.MakeHTTPTracingMW(tracer, ComponentName, "http_server_event")(eventHandler)
		}
		eventSubroute.Handle("/receiver", eventHandler)

		// Export.
		route.Handle("/export", export.MakeHTTPExportHandler(exportEndpoint)).Methods("GET")
		route.Handle("/export", export.MakeHTTPExportHandler(exportSaveAndExportEndpoint)).Methods("POST")

		// Debug.
		if pprofRouteEnabled {
			var debugSubroute = route.PathPrefix("/debug").Subrouter()
			debugSubroute.HandleFunc("/pprof/", http.HandlerFunc(pprof.Index))
			debugSubroute.HandleFunc("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
			debugSubroute.HandleFunc("/pprof/profile", http.HandlerFunc(pprof.Profile))
			debugSubroute.HandleFunc("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
			debugSubroute.HandleFunc("/pprof/trace", http.HandlerFunc(pprof.Trace))
		}

		errc <- http.ListenAndServe(httpAddrInternal, route)
	}()

	// HTTP Management Server (Backoffice API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Log("addr", httpAddrManagement)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", http.HandlerFunc(makeVersion(ComponentName, ComponentID, Version, Environment, GitCommit)))

		// Events
		var getEventsHandler = configureEventsHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(eventsEndpoints.GetEvents)
		var getEventsSummaryHandler = configureEventsHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(eventsEndpoints.GetEventsSummary)
		var getUserEventsHandler = configureEventsHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(eventsEndpoints.GetUserEvents)

		route.Path("/events").Methods("GET").Handler(getEventsHandler)
		route.Path("/events/summary").Methods("GET").Handler(getEventsSummaryHandler)
		route.Path("/events/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/events").Methods("GET").Handler(getUserEventsHandler)

		// Management
		var managementSubroute = route.PathPrefix("/management").Subrouter()

		var getRealmsHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealms)
		var getRealmHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealm)

		var getClientsHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClients)
		var getClientHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClient)

		var createUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateUser)
		var getUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUser)
		var updateUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UpdateUser)
		var deleteUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteUser)
		var getUsersHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUsers)

		var getUserAccountStatusHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUserAccountStatus)

		var getClientRoleForUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClientRoleForUser)
		var addClientRoleToUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.AddClientRoleToUser)
		var getRealmRoleForUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealmRoleForUser)

		var getRolesHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRoles)
		var getRoleHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRole)
		var getClientRolesHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClientRoles)
		var createClientRolesHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateClientRole)

		var resetPasswordHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ResetPassword)
		var sendVerifyEmailHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SendVerifyEmail)
		var executeActionsEmailHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ExecuteActionsEmail)
		var sendNewEnrolmentCodeHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SendNewEnrolmentCode)

		var getCredentialsForUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetCredentialsForUser)
		var deleteCredentialsForUserHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteCredentialsForUser)

		var getRealmCustomConfigurationHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealmCustomConfiguration)
		var updateRealmCustomConfigurationHandler = configureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UpdateRealmCustomConfiguration)

		//realms
		managementSubroute.Path("/realms").Methods("GET").Handler(getRealmsHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}").Methods("GET").Handler(getRealmHandler)

		//clients
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/clients").Methods("GET").Handler(getClientsHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/clients/{clientID:[a-zA-Z0-9-]+}").Methods("GET").Handler(getClientHandler)

		//users
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users").Methods("GET").Handler(getUsersHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users").Methods("POST").Handler(createUserHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}").Methods("GET").Handler(getUserHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}").Methods("PUT").Handler(updateUserHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}").Methods("DELETE").Handler(deleteUserHandler)

		// account status
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/status").Methods("GET").Handler(getUserAccountStatusHandler)

		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/role-mappings/clients/{clientID:[a-zA-Z0-9-]+}").Methods("GET").Handler(getClientRoleForUserHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/role-mappings/clients/{clientID:[a-zA-Z0-9-]+}").Methods("POST").Handler(addClientRoleToUserHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/role-mappings/realm").Methods("GET").Handler(getRealmRoleForUserHandler)

		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/reset-password").Methods("PUT").Handler(resetPasswordHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/send-verify-email").Methods("PUT").Handler(sendVerifyEmailHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/execute-actions-email").Methods("PUT").Handler(executeActionsEmailHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/send-new-enrolment-code").Methods("POST").Handler(sendNewEnrolmentCodeHandler)

		// Credentials
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/credentials").Methods("GET").Handler(getCredentialsForUserHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/users/{userID:[a-zA-Z0-9-]+}/credentials/{credentialID:[a-zA-Z0-9-]+}").Methods("DELETE").Handler(deleteCredentialsForUserHandler)

		//roles
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/roles").Methods("GET").Handler(getRolesHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/roles-by-id/{roleID:[a-zA-Z0-9-]+}").Methods("GET").Handler(getRoleHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/clients/{clientID:[a-zA-Z0-9-]+}/roles").Methods("GET").Handler(getClientRolesHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/clients/{clientID:[a-zA-Z0-9-]+}/roles").Methods("POST").Handler(createClientRolesHandler)

		// custom configuration par realm
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/configuration").Methods("GET").Handler(getRealmCustomConfigurationHandler)
		managementSubroute.Path("/realms/{realm:[a-zA-Z0-9_-]+}/configuration").Methods("PUT").Handler(updateRealmCustomConfigurationHandler)

		c := cors.New(corsOptions)
		errc <- http.ListenAndServe(httpAddrManagement, c.Handler(route))

	}()

	// HTTP Self-service Server (Account API). 
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Log("addr", httpAddrAccount)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", http.HandlerFunc(makeVersion(ComponentName, ComponentID, Version, Environment, GitCommit)))

		// Account
		var updatePasswordHandler = configureAccountHandler(ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.UpdatePassword)
		route.Path("/account/credentials/password").Methods("POST").Handler(updatePasswordHandler)

		c := cors.New(corsOptions)
		errc <- http.ListenAndServe(httpAddrAccount, c.Handler(route))
	}()

	// Influx writing.
	go func() {
		var tic = time.NewTicker(influxWriteInterval)
		defer tic.Stop()
		influxMetrics.WriteLoop(tic.C)
	}()

	logger.Log("msg", "Started")
	logger.Log("error", <-errc)
}

// makeVersion makes a HTTP handler that returns information about the version of the bridge.
func makeVersion(componentName, ComponentID, version, environment, gitCommit string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		var info = struct {
			Name    string `json:"name"`
			ID      string `json:"id"`
			Version string `json:"version"`
			Env     string `json:"environment"`
			Commit  string `json:"commit"`
		}{
			Name:    ComponentName,
			ID:      ComponentID,
			Version: version,
			Env:     environment,
			Commit:  gitCommit,
		}

		var j, err = json.MarshalIndent(info, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	}
}

func config(logger log.Logger) *viper.Viper {
	logger.Log("msg", "load configuration and command args")

	var v = viper.New()

	// Component default.
	v.SetDefault("config-file", "./configs/keycloak_bridge.yml")
	v.SetDefault("authorization-file", "./configs/authorization.json")

	// Publishing
	v.SetDefault("internal-http-host-port", "0.0.0.0:8888")
	v.SetDefault("management-http-host-port", "0.0.0.0:8877")
	v.SetDefault("account-http-host-port", "0.0.0.0:8866")

	// Security - Audience check
	v.SetDefault("audience", "")

	// CORS configuration
	v.SetDefault("cors-allowed-origins", []string{})
	v.SetDefault("cors-allowed-methods", []string{})
	v.SetDefault("cors-allow-credentials", true)
	v.SetDefault("cors-allowed-headers", []string{})
	v.SetDefault("cors-debug", false)

	// Keycloak default.
	v.SetDefault("keycloak", true)
	v.SetDefault("keycloak-api-uri", "http://127.0.0.1:8080")
	v.SetDefault("keycloak-oidc-uri", "http://127.0.0.1:8080")
	v.SetDefault("keycloak-username", "")
	v.SetDefault("keycloak-password", "")
	v.SetDefault("keycloak-timeout", "5s")

	// Storage events in DB (read/write)
	v.SetDefault("events-db", false)
	configureDbDefault(v, "db-audit-rw")

	// Storage events in DB (read only)
	configureDbDefault(v, "db-audit-ro")

	//Storage custom configuration in DB
	v.SetDefault("config-db", true)
	configureDbDefault(v, "db-config")

	// Rate limiting (in requests/second)
	v.SetDefault("rate-event", 1000)
	v.SetDefault("rate-management", 1000)

	// Influx DB client default.
	v.SetDefault("influx", false)
	v.SetDefault("influx-host-port", "")
	v.SetDefault("influx-username", "")
	v.SetDefault("influx-password", "")
	v.SetDefault("influx-database", "")
	v.SetDefault("influx-precision", "")
	v.SetDefault("influx-retention-policy", "")
	v.SetDefault("influx-write-consistency", "")
	v.SetDefault("influx-write-interval", "1s")

	// Sentry client default.
	v.SetDefault("sentry", false)
	v.SetDefault("sentry-dsn", "")

	// Jaeger tracing default.
	v.SetDefault("jaeger", false)
	v.SetDefault("jaeger-sampler-type", "")
	v.SetDefault("jaeger-sampler-param", 0)
	v.SetDefault("jaeger-sampler-host-port", "")
	v.SetDefault("jaeger-reporter-logspan", false)
	v.SetDefault("jaeger-write-interval", "1s")

	// Debug routes enabled.
	v.SetDefault("pprof-route-enabled", true)

	// First level of override.
	pflag.String("config-file", v.GetString("config-file"), "The configuration file path can be relative or absolute.")
	pflag.String("authorization-file", v.GetString("authorization-file"), "The authorization file path can be relative or absolute.")
	v.BindPFlag("config-file", pflag.Lookup("config-file"))
	v.BindPFlag("authorization-file", pflag.Lookup("authorization-file"))
	pflag.Parse()

	// Load and log config.
	v.SetConfigFile(v.GetString("config-file"))
	var err = v.ReadInConfig()
	if err != nil {
		logger.Log("error", err)
	}

	// If the host/port is not set, we consider the components deactivated.
	v.Set("influx", v.GetString("influx-host-port") != "")
	v.Set("sentry", v.GetString("sentry-dsn") != "")
	v.Set("jaeger", v.GetString("jaeger-sampler-host-port") != "")

	// Log config in alphabetical order.
	var keys = v.AllKeys()
	sort.Strings(keys)

	for _, k := range keys {
		logger.Log(k, v.Get(k))
	}
	return v
}

func configureDbDefault(v *viper.Viper, prefix string) {
	v.SetDefault(prefix+"-host-port", "")
	v.SetDefault(prefix+"-username", "")
	v.SetDefault(prefix+"-password", "")
	v.SetDefault(prefix+"-database", "")
	v.SetDefault(prefix+"-protocol", "")
	v.SetDefault(prefix+"-max-open-conns", 10)
	v.SetDefault(prefix+"-max-idle-conns", 2)
	v.SetDefault(prefix+"-conn-max-lifetime", 3600)
}

func getDbConfig(v *viper.Viper, prefix string) *dbConfig {
	var cfg dbConfig
	cfg.HostPort = v.GetString(prefix + "-host-port")
	cfg.Username = v.GetString(prefix + "-username")
	cfg.Password = v.GetString(prefix + "-password")
	cfg.Database = v.GetString(prefix + "-database")
	cfg.Protocol = v.GetString(prefix + "-protocol")
	cfg.MaxOpenConns = v.GetInt(prefix + "-max-open-conns")
	cfg.MaxIdleConns = v.GetInt(prefix + "-max-idle-conns")
	cfg.ConnMaxLifetime = v.GetInt(prefix + "-conn-max-lifetime")

	return &cfg
}

func (cfg *dbConfig) openDatabase() (*sql.DB, error) {
	var err error
	var dbConn *sql.DB
	dbConn, err = sql.Open("mysql", fmt.Sprintf("%s:%s@%s(%s)/%s", cfg.Username, cfg.Password, cfg.Protocol, cfg.HostPort, cfg.Database))

	// the config of the DB should have a max_connections > SetMaxOpenConns
	if err == nil {
		dbConn.SetMaxOpenConns(cfg.MaxOpenConns)
		dbConn.SetMaxIdleConns(cfg.MaxIdleConns)
		dbConn.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)
	}

	return dbConn, err
}

func configureEventsHandler(ComponentName string, ComponentID string, idGenerator gen.IDGenerator, keycloakClient *keycloak.Client, audienceRequired string, tracer opentracing.Tracer, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = events.MakeEventsHandler(endpoint)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureManagementHandler(ComponentName string, ComponentID string, idGenerator gen.IDGenerator, keycloakClient *keycloak.Client, audienceRequired string, tracer opentracing.Tracer, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = management.MakeManagementHandler(endpoint)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureAccountHandler(ComponentName string, ComponentID string, idGenerator gen.IDGenerator, keycloakClient *keycloak.Client, audienceRequired string, tracer opentracing.Tracer, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = account.MakeAccountHandler(endpoint)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureEventsDbModule(baseEventsDBModule event.EventsDBModule, influxMetrics Metrics, logger log.Logger, tracer opentracing.Tracer) event.EventsDBModule {
	eventsDBModule := event.MakeEventsDBModuleInstrumentingMW(influxMetrics.NewHistogram("eventsDB_module"))(baseEventsDBModule)
	eventsDBModule = event.MakeEventsDBModuleLoggingMW(log.With(logger, "mw", "module", "unit", "eventsDB"))(eventsDBModule)
	eventsDBModule = event.MakeEventsDBModuleTracingMW(tracer)(eventsDBModule)
	return eventsDBModule
}

func prepareEndpoint(e endpoint.Endpoint, endpointName string, influxMetrics Metrics, managementLogger log.Logger, tracer opentracing.Tracer, rateLimit map[string]int) endpoint.Endpoint {
	e = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram(endpointName))(e)
	e = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(e)
	e = middleware.MakeEndpointTracingMW(tracer, endpointName)(e)
	e = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(e)

	return e
}
