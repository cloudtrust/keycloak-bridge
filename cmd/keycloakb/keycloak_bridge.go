package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/idgenerator"
	gen "github.com/cloudtrust/keycloak-bridge/internal/idgenerator"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/event"
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

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	// Logger.
	var logger = log.NewJSONLogger(os.Stdout)
	{
		logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	}
	defer logger.Log("msg", "goodbye")

	ComponentID = strconv.FormatUint(rand.Uint64(), 10)

	// Configurations.
	var c = config(log.With(logger, "unit", "config"))
	var (
		// Component
		httpAddr = c.GetString("component-http-host-port")

		// Keycloak
		keycloakConfig = keycloak.Config{
			AddrTokenProvider: c.GetString("keycloak-oidc-uri"),
			AddrAPI:           c.GetString("keycloak-api-uri"),
			Timeout:           c.GetDuration("keycloak-timeout"),
		}

		// Enabled units
		eventsDBEnabled   = c.GetBool("events-db")
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
		dbHostPort        = c.GetString("db-host-port")
		dbUsername        = c.GetString("db-username")
		dbPassword        = c.GetString("db-password")
		dbDatabase        = c.GetString("db-database")
		dbProtocol        = c.GetString("db-protocol")
		dbMaxOpenConns    = c.GetInt("db-max-open-conns")
		dbMaxIdleConns    = c.GetInt("db-max-idle-conns")
		dbConnMaxLifetime = c.GetInt("db-conn-max-lifetime")

		// Rate limiting
		rateLimit = map[string]int{
			"event":      c.GetInt("rate-event"),
			"management": c.GetInt("rate-management"),
		}
	)

	// Unique ID generator
	var idGenerator = idgenerator.New(ComponentName, ComponentID)

	// Add component name, component ID and version to the logger tags.
	logger = log.With(logger, "component_name", ComponentName, "component_id", ComponentID, "component_version", Version)

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

	// Influx client.
	type Metrics interface {
		NewCounter(name string) metrics.Counter
		NewGauge(name string) metrics.Gauge
		NewHistogram(name string) metrics.Histogram
		WriteLoop(c <-chan time.Time)
		Write(bp influx.BatchPoints) error
		Ping(timeout time.Duration) (time.Duration, string, error)
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
	type EventsDB interface {
		Exec(query string, args ...interface{}) (sql.Result, error)
		//Ping() error
		Query(query string, args ...interface{}) (*sql.Rows, error)
		QueryRow(query string, args ...interface{}) *sql.Row
		SetMaxOpenConns(n int)
		SetMaxIdleConns(n int)
		SetConnMaxLifetime(d time.Duration)
	}

	var eventsDBConn EventsDB = keycloakb.NoopEventsDB{}
	if eventsDBEnabled {
		var err error
		eventsDBConn, err = sql.Open("mysql", fmt.Sprintf("%s:%s@%s(%s)/%s", dbUsername, dbPassword, dbProtocol, dbHostPort, dbDatabase))

		if err != nil {
			logger.Log("msg", "could not create DB connection for audit events", "error", err)
			return
		}
		// the config of the DB should have a max_connections > SetMaxOpenConns
		eventsDBConn.SetMaxOpenConns(dbMaxOpenConns)
		eventsDBConn.SetMaxIdleConns(dbMaxIdleConns)
		eventsDBConn.SetConnMaxLifetime(time.Duration(dbConnMaxLifetime) * time.Second)

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

	// Management service.
	var managementEndpoints = management.Endpoints{}
	{
		var managementLogger = log.With(logger, "svc", "management")

		var keycloakComponent management.Component
		{
			keycloakComponent = management.NewComponent(keycloakClient)
		}

		var getRealmEndpoint endpoint.Endpoint
		{
			getRealmEndpoint = management.MakeGetRealmEndpoint(keycloakComponent)
			getRealmEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("realm_endpoint"))(getRealmEndpoint)
			getRealmEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getRealmEndpoint)
			getRealmEndpoint = middleware.MakeEndpointTracingMW(tracer, "realm_endpoint")(getRealmEndpoint)
			getRealmEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getRealmEndpoint)
			getRealmEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getRealmEndpoint)
		}

		var getClientEndpoint endpoint.Endpoint
		{
			getClientEndpoint = management.MakeGetClientEndpoint(keycloakComponent)
			getClientEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_client_endpoint"))(getClientEndpoint)
			getClientEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getClientEndpoint)
			getClientEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_client_endpoint")(getClientEndpoint)
			getClientEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getClientEndpoint)
			getClientEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getClientEndpoint)
		}

		var getClientsEndpoint endpoint.Endpoint
		{
			getClientsEndpoint = management.MakeGetClientsEndpoint(keycloakComponent)
			getClientsEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_clients_endpoint"))(getClientsEndpoint)
			getClientsEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getClientsEndpoint)
			getClientsEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_clients_endpoint")(getClientsEndpoint)
			getClientsEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getClientsEndpoint)
			getClientsEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getClientsEndpoint)
		}

		var getUserEndpoint endpoint.Endpoint
		{
			getUserEndpoint = management.MakeGetUserEndpoint(keycloakComponent)
			getUserEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_user_endpoint"))(getUserEndpoint)
			getUserEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getUserEndpoint)
			getUserEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_user_endpoint")(getUserEndpoint)
			getUserEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getUserEndpoint)
			getUserEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getUserEndpoint)
		}

		var createUserEndpoint endpoint.Endpoint
		{
			createUserEndpoint = management.MakeCreateUserEndpoint(keycloakComponent)
			createUserEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("create_user_endpoint"))(createUserEndpoint)
			createUserEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(createUserEndpoint)
			createUserEndpoint = middleware.MakeEndpointTracingMW(tracer, "create_user_endpoint")(createUserEndpoint)
			createUserEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(createUserEndpoint)
			createUserEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(createUserEndpoint)
		}

		var updateUserEndpoint endpoint.Endpoint
		{
			updateUserEndpoint = management.MakeUpdateUserEndpoint(keycloakComponent)
			updateUserEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("update_user_endpoint"))(updateUserEndpoint)
			updateUserEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(updateUserEndpoint)
			updateUserEndpoint = middleware.MakeEndpointTracingMW(tracer, "update_user_endpoint")(updateUserEndpoint)
			updateUserEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(updateUserEndpoint)
			updateUserEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(updateUserEndpoint)
		}

		var deleteUserEndpoint endpoint.Endpoint
		{
			deleteUserEndpoint = management.MakeDeleteUserEndpoint(keycloakComponent)
			deleteUserEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("delete_user_endpoint"))(deleteUserEndpoint)
			deleteUserEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(deleteUserEndpoint)
			deleteUserEndpoint = middleware.MakeEndpointTracingMW(tracer, "delete_user_endpoint")(deleteUserEndpoint)
			deleteUserEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(deleteUserEndpoint)
			deleteUserEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(deleteUserEndpoint)
		}

		var getUsersEndpoint endpoint.Endpoint
		{
			getUsersEndpoint = management.MakeGetUsersEndpoint(keycloakComponent)
			getUsersEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_users_endpoint"))(getUsersEndpoint)
			getUsersEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getUsersEndpoint)
			getUsersEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_users_endpoint")(getUsersEndpoint)
			getUsersEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getUsersEndpoint)
			getUsersEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getUsersEndpoint)
		}

		var getRolesEndpoint endpoint.Endpoint
		{
			getRolesEndpoint = management.MakeGetRolesEndpoint(keycloakComponent)
			getRolesEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_roles_endpoint"))(getRolesEndpoint)
			getRolesEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getRolesEndpoint)
			getRolesEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_roles_endpoint")(getRolesEndpoint)
			getRolesEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getRolesEndpoint)
			getRolesEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getRolesEndpoint)
		}

		var getRoleEndpoint endpoint.Endpoint
		{
			getRoleEndpoint = management.MakeGetRoleEndpoint(keycloakComponent)
			getRoleEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_role_endpoint"))(getRoleEndpoint)
			getRoleEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getRoleEndpoint)
			getRoleEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_role_endpoint")(getRoleEndpoint)
			getRoleEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getRoleEndpoint)
			getRoleEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getRoleEndpoint)
		}

		var createClientRoleEndpoint endpoint.Endpoint
		{
			createClientRoleEndpoint = management.MakeCreateClientRoleEndpoint(keycloakComponent)
			createClientRoleEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("create_client_role_endpoint"))(createClientRoleEndpoint)
			createClientRoleEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(createClientRoleEndpoint)
			createClientRoleEndpoint = middleware.MakeEndpointTracingMW(tracer, "create_client_role_endpoint")(createClientRoleEndpoint)
			createClientRoleEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(createClientRoleEndpoint)
			createClientRoleEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(createClientRoleEndpoint)
		}

		var getClientRolesEndpoint endpoint.Endpoint
		{
			getClientRolesEndpoint = management.MakeGetClientRolesEndpoint(keycloakComponent)
			getClientRolesEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_client_roles_endpoint"))(getClientRolesEndpoint)
			getClientRolesEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getClientRolesEndpoint)
			getClientRolesEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_client_roles_endpoint")(getClientRolesEndpoint)
			getClientRolesEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getClientRolesEndpoint)
			getClientRolesEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getClientRolesEndpoint)
		}

		var getClientRolesForUserEndpoint endpoint.Endpoint
		{
			getClientRolesForUserEndpoint = management.MakeGetClientRolesForUserEndpoint(keycloakComponent)
			getClientRolesForUserEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_client_roles_for_user_endpoint"))(getClientRolesForUserEndpoint)
			getClientRolesForUserEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getClientRolesForUserEndpoint)
			getClientRolesForUserEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_client_roles_for_user_endpoint")(getClientRolesForUserEndpoint)
			getClientRolesForUserEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getClientRolesForUserEndpoint)
			getClientRolesForUserEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getClientRolesForUserEndpoint)
		}

		var addClientRolesToUserEndpoint endpoint.Endpoint
		{
			addClientRolesToUserEndpoint = management.MakeAddClientRolesToUserEndpoint(keycloakComponent)
			addClientRolesToUserEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_client_roles_for_user_endpoint"))(addClientRolesToUserEndpoint)
			addClientRolesToUserEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(addClientRolesToUserEndpoint)
			addClientRolesToUserEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_client_roles_for_user_endpoint")(addClientRolesToUserEndpoint)
			addClientRolesToUserEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(addClientRolesToUserEndpoint)
			addClientRolesToUserEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(addClientRolesToUserEndpoint)
		}

		var getRealmRolesForUserEndpoint endpoint.Endpoint
		{
			getRealmRolesForUserEndpoint = management.MakeGetRealmRolesForUserEndpoint(keycloakComponent)
			getRealmRolesForUserEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("get_realm_roles_for_user_endpoint"))(getRealmRolesForUserEndpoint)
			getRealmRolesForUserEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(getRealmRolesForUserEndpoint)
			getRealmRolesForUserEndpoint = middleware.MakeEndpointTracingMW(tracer, "get_realm_roles_for_user_endpoint")(getRealmRolesForUserEndpoint)
			getRealmRolesForUserEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(getRealmRolesForUserEndpoint)
			getRealmRolesForUserEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(getRealmRolesForUserEndpoint)
		}

		var resetPasswordEndpoint endpoint.Endpoint
		{
			resetPasswordEndpoint = management.MakeResetPasswordEndpoint(keycloakComponent)
			resetPasswordEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("reset_password_endpoint"))(resetPasswordEndpoint)
			resetPasswordEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(resetPasswordEndpoint)
			resetPasswordEndpoint = middleware.MakeEndpointTracingMW(tracer, "reset_password_endpoint")(resetPasswordEndpoint)
			resetPasswordEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(resetPasswordEndpoint)
			resetPasswordEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(resetPasswordEndpoint)
		}

		var sendVerifyEmailEndpoint endpoint.Endpoint
		{
			sendVerifyEmailEndpoint = management.MakeSendVerifyEmailEndpoint(keycloakComponent)
			sendVerifyEmailEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics.NewHistogram("send_verify_email_endpoint"))(sendVerifyEmailEndpoint)
			sendVerifyEmailEndpoint = middleware.MakeEndpointLoggingMW(log.With(managementLogger, "mw", "endpoint"))(sendVerifyEmailEndpoint)
			sendVerifyEmailEndpoint = middleware.MakeEndpointTracingMW(tracer, "send_verify_email_endpoint")(sendVerifyEmailEndpoint)
			sendVerifyEmailEndpoint = middleware.MakeEndpointTokenForRealmMW(log.With(managementLogger, "mw", "endpoint"))(sendVerifyEmailEndpoint)
			sendVerifyEmailEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit["management"]))(sendVerifyEmailEndpoint)
		}

		managementEndpoints = management.Endpoints{
			GetRealm:             getRealmEndpoint,
			GetClients:           getClientsEndpoint,
			GetClient:            getClientEndpoint,
			CreateUser:           createUserEndpoint,
			GetUser:              getUserEndpoint,
			UpdateUser:           updateUserEndpoint,
			DeleteUser:           deleteUserEndpoint,
			GetUsers:             getUsersEndpoint,
			GetRoles:             getRolesEndpoint,
			GetRole:              getRoleEndpoint,
			GetClientRoles:       getClientRolesEndpoint,
			CreateClientRole:     createClientRoleEndpoint,
			GetClientRoleForUser: getClientRolesForUserEndpoint,
			AddClientRoleToUser:  addClientRolesToUserEndpoint,
			GetRealmRoleForUser:  getRealmRolesForUserEndpoint,
			ResetPassword:        resetPasswordEndpoint,
			SendVerifyEmail:      sendVerifyEmailEndpoint,
		}
	}

	// Export configuration
	var exportModule = export.NewModule(keycloakClient)
	var cfgStorageModue = export.NewConfigStorageModule(eventsDBConn)

	var exportComponent = export.NewComponent(ComponentName, Version, exportModule, cfgStorageModue)
	var exportEndpoint = export.MakeExportEndpoint(exportComponent)
	var exportSaveAndExportEndpoint = export.MakeStoreAndExportEndpoint(exportComponent)

	// HTTP Server.
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Log("addr", httpAddr)

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

		// Management
		var managementSubroute = route.PathPrefix("/management").Subrouter()

		var getRealmHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetRealm)

		var getClientsHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetClients)
		var getClientHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetClient)

		var createUserHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.CreateUser)
		var getUserHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetUser)
		var updateUserHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.UpdateUser)
		var deleteUserHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.DeleteUser)
		var getUsersHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetUsers)

		var getClientRoleForUserHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetClientRoleForUser)
		var addClientRoleToUserHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.AddClientRoleToUser)
		var getRealmRoleForUserHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetRealmRoleForUser)

		var getRolesHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetRoles)
		var getRoleHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetRole)
		var getClientRolesHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.GetClientRoles)
		var createClientRolesHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.CreateClientRole)

		var resetPasswordHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.ResetPassword)
		var sendVerifyEmailHandler = ConfigureManagementHandler(ComponentName, ComponentID, idGenerator, keycloakClient, tracer, logger)(managementEndpoints.SendVerifyEmail)

		//realms
		managementSubroute.Path("/realms/{realm}").Methods("GET").Handler(getRealmHandler)

		//clients
		managementSubroute.Path("/realms/{realm}/clients").Methods("GET").Handler(getClientsHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}").Methods("GET").Handler(getClientHandler)

		//users
		managementSubroute.Path("/realms/{realm}/users").Methods("GET").Handler(getUsersHandler)
		managementSubroute.Path("/realms/{realm}/users").Methods("POST").Handler(createUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("GET").Handler(getUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("PUT").Handler(updateUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("DELETE").Handler(deleteUserHandler)

		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("GET").Handler(getClientRoleForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("POST").Handler(addClientRoleToUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/realm").Methods("GET").Handler(getRealmRoleForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/reset-password").Methods("PUT").Handler(resetPasswordHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-verify-email").Methods("PUT").Handler(sendVerifyEmailHandler)
		//roles
		managementSubroute.Path("/realms/{realm}/roles").Methods("GET").Handler(getRolesHandler)
		managementSubroute.Path("/realms/{realm}/roles-by-id/{roleID}").Methods("GET").Handler(getRoleHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}/roles").Methods("GET").Handler(getClientRolesHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}/roles").Methods("POST").Handler(createClientRolesHandler)

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

		errc <- http.ListenAndServe(httpAddr, route)
	}()

	// Influx writing.
	go func() {
		var tic = time.NewTicker(influxWriteInterval)
		defer tic.Stop()
		influxMetrics.WriteLoop(tic.C)
	}()

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
	v.SetDefault("component-http-host-port", "0.0.0.0:8888")

	// Keycloak default.
	v.SetDefault("keycloak", true)
	v.SetDefault("keycloak-api-uri", "http://127.0.0.1:8080")
	v.SetDefault("keycloak-oidc-uri", "http://127.0.0.1:8080")
	v.SetDefault("keycloak-username", "")
	v.SetDefault("keycloak-password", "")
	v.SetDefault("keycloak-timeout", "5s")

	//Storage events in DB
	v.SetDefault("events-DB", false)
	v.SetDefault("db-host-port", "")
	v.SetDefault("db-username", "")
	v.SetDefault("db-password", "")
	v.SetDefault("db-database", "")
	v.SetDefault("db-table", "")
	v.SetDefault("protocol", "")

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
	v.BindPFlag("config-file", pflag.Lookup("config-file"))
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

func ConfigureManagementHandler(ComponentName string, ComponentID string, idGenerator gen.IDGenerator, keycloakClient *keycloak.Client, tracer opentracing.Tracer, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = management.MakeManagementHandler(endpoint)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, logger)(handler)
		return handler
	}
}
