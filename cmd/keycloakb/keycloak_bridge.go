package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/database/sqltypes"
	"github.com/cloudtrust/common-service/healthcheck"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/idgenerator"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/metrics"
	"github.com/cloudtrust/common-service/middleware"
	"github.com/cloudtrust/common-service/security"
	"github.com/cloudtrust/common-service/tracing"
	"github.com/cloudtrust/common-service/tracking"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/event"
	"github.com/cloudtrust/keycloak-bridge/pkg/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/export"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc"
	"github.com/cloudtrust/keycloak-bridge/pkg/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation"
	keycloak "github.com/cloudtrust/keycloak-client"
	keycloakapi "github.com/cloudtrust/keycloak-client/api"
	"github.com/cloudtrust/keycloak-client/toolbox"
	"github.com/go-kit/kit/endpoint"
	kit_log "github.com/go-kit/kit/log"
	kit_level "github.com/go-kit/kit/log/level"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	// ComponentID is an unique ID generated at component startup.
	ComponentID = "unknown"
	// Environment is filled by the compiler.
	Environment = "unknown"
	// GitCommit is filled by the compiler.
	GitCommit = "unknown"
)

// RateKey is used for rate limits
type RateKey int

// Constants
const (
	defaultPublishingIP = "0.0.0.0"

	RateKeyAccount    = iota
	RateKeyEvent      = iota
	RateKeyEvents     = iota
	RateKeyKYC        = iota
	RateKeyManagement = iota
	RateKeyRegister   = iota
	RateKeyStatistics = iota
	RateKeyValidation = iota

	CfgConfigFile               = "config-file"
	CfgHTTPAddrInternal         = "internal-http-host-port"
	CfgHTTPAddrManagement       = "management-http-host-port"
	CfgHTTPAddrAccount          = "account-http-host-port"
	CfgHTTPAddrRegister         = "register-http-host-port"
	CfgAddrTokenProvider        = "keycloak-oidc-uri"
	CfgAddrAPI                  = "keycloak-api-uri"
	CfgTimeout                  = "keycloak-timeout"
	CfgAudienceRequired         = "audience-required"
	CfgEventBasicAuthToken      = "event-basic-auth-token"
	CfgValidationBasicAuthToken = "validation-basic-auth-token"
	CfgPprofRouteEnabled        = "pprof-route-enabled"
	CfgInfluxWriteInterval      = "influx-write-interval"
	CfgSentryDsn                = "sentry-dsn"
	CfgAuditRwDbParams          = "db-audit-rw"
	CfgAuditRoDbParams          = "db-audit-ro"
	CfgConfigRwDbParams         = "db-config-rw"
	CfgConfigRoDbParams         = "db-config-ro"
	CfgUsersRwDbParams          = "db-users-rw"
	CfgRateKeyValidation        = "rate-validation"
	CfgRateKeyEvent             = "rate-event"
	CfgRateKeyAccount           = "rate-account"
	CfgRateKeyManagement        = "rate-management"
	CfgRateKeyStatistics        = "rate-statistics"
	CfgRateKeyEvents            = "rate-events"
	CfgRateKeyRegister          = "rate-register"
	CfgRateKeyKYC               = "rate-kyc"
	CfgAllowedOrigins           = "cors-allowed-origins"
	CfgAllowedMethods           = "cors-allowed-methods"
	CfgAllowCredentials         = "cors-allow-credentials"
	CfgAllowedHeaders           = "cors-allowed-headers"
	CfgExposedHeaders           = "cors-exposed-headers"
	CfgDebug                    = "cors-debug"
	CfgLogLevel                 = "log-level"
	CfgAccessLogsEnabled        = "access-logs"
	CfgTrustIDGroups            = "trustid-groups"
	CfgRegisterEnabled          = "register-enabled"
	CfgRegisterRealm            = "register-realm"
	CfgRegisterUsername         = "register-techuser-username"
	CfgRegisterPassword         = "register-techuser-password"
	CfgRegisterClientID         = "register-techuser-client-id"
	CfgRegisterEnduserClientID  = "register-enduser-client-id"
	CfgRecaptchaURL             = "recaptcha-url"
	CfgRecaptchaSecret          = "recaptcha-secret"
	CfgSsePublicURL             = "sse-public-url"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	ComponentID := strconv.FormatUint(rand.Uint64(), 10)
	ctx := context.Background()

	// Access log logger
	var accessLogger = kit_log.NewJSONLogger(os.Stdout)
	{
		// Timestamp
		accessLogger = kit_log.With(accessLogger, "_ts", kit_log.DefaultTimestampUTC)

		// Add component name, component ID and version to the logger tags.
		accessLogger = kit_log.With(accessLogger, "component_name", keycloakb.ComponentName, "component_id", ComponentID, "component_version", keycloakb.Version)

		// Add access_log type
		accessLogger = kit_log.With(accessLogger, "type", "access_log")
	}

	// Leveled Logger.
	var logger = log.NewLeveledLogger(kit_log.NewJSONLogger(os.Stdout))
	{
		// Timestamp
		logger = log.With(logger, "_ts", kit_log.DefaultTimestampUTC)

		// Caller
		logger = log.With(logger, "caller", kit_log.Caller(6))

		// Add component name, component ID and version to the logger tags.
		logger = log.With(logger, "component_name", keycloakb.ComponentName, "component_id", ComponentID, "component_version", keycloakb.Version)
	}
	defer logger.Info(ctx, "msg", "Shutdown")

	// Log component version infos.
	logger.Info(ctx, "msg", "Starting")
	logger.Info(ctx, "environment", Environment, "git_commit", GitCommit)

	// Configurations.
	var c = config(ctx, log.With(logger, "unit", "config"))
	var (
		// Publishing
		httpAddrInternal   = c.GetString(CfgHTTPAddrInternal)
		httpAddrManagement = c.GetString(CfgHTTPAddrManagement)
		httpAddrAccount    = c.GetString(CfgHTTPAddrAccount)
		httpAddrRegister   = c.GetString(CfgHTTPAddrRegister)

		// Keycloak
		keycloakConfig = keycloak.Config{
			AddrTokenProvider: c.GetString(CfgAddrTokenProvider),
			AddrAPI:           c.GetString(CfgAddrAPI),
			Timeout:           c.GetDuration(CfgTimeout),
		}

		// Enabled units
		pprofRouteEnabled = c.GetBool(CfgPprofRouteEnabled)

		// Influx
		influxWriteInterval = c.GetDuration(CfgInfluxWriteInterval)

		// DB - for the moment used just for audit events
		auditRwDbParams = database.GetDbConfig(c, CfgAuditRwDbParams)

		// DB - Read only user for audit events
		auditRoDbParams = database.GetDbConfig(c, CfgAuditRoDbParams)

		// DB for custom configuration
		configRwDbParams = database.GetDbConfig(c, CfgConfigRwDbParams)
		configRoDbParams = database.GetDbConfig(c, CfgConfigRoDbParams)

		// DB for users
		usersRwDbParams = database.GetDbConfig(c, CfgUsersRwDbParams)

		// Rate limiting
		rateLimit = map[RateKey]int{
			RateKeyValidation: c.GetInt(CfgRateKeyValidation),
			RateKeyEvent:      c.GetInt(CfgRateKeyEvent),
			RateKeyAccount:    c.GetInt(CfgRateKeyAccount),
			RateKeyManagement: c.GetInt(CfgRateKeyManagement),
			RateKeyStatistics: c.GetInt(CfgRateKeyStatistics),
			RateKeyEvents:     c.GetInt(CfgRateKeyEvents),
			RateKeyRegister:   c.GetInt(CfgRateKeyRegister),
			RateKeyKYC:        c.GetInt(CfgRateKeyKYC),
		}

		corsOptions = cors.Options{
			AllowedOrigins:   c.GetStringSlice(CfgAllowedOrigins),
			AllowedMethods:   c.GetStringSlice(CfgAllowedMethods),
			AllowCredentials: c.GetBool(CfgAllowCredentials),
			AllowedHeaders:   c.GetStringSlice(CfgAllowedHeaders),
			ExposedHeaders:   c.GetStringSlice(CfgExposedHeaders),
			Debug:            c.GetBool(CfgDebug),
		}

		logLevel = c.GetString(CfgLogLevel)

		// Access logs
		accessLogsEnabled = c.GetBool(CfgAccessLogsEnabled)

		// Register parameters
		registerEnabled         = c.GetBool(CfgRegisterEnabled)
		registerRealm           = c.GetString(CfgRegisterRealm)
		registerUsername        = c.GetString(CfgRegisterUsername)
		registerPassword        = c.GetString(CfgRegisterPassword)
		registerClientID        = c.GetString(CfgRegisterClientID)
		registerEnduserClientID = c.GetString(CfgRegisterEnduserClientID)
		recaptchaURL            = c.GetString(CfgRecaptchaURL)
		recaptchaSecret         = c.GetString(CfgRecaptchaSecret)
		ssePublicURL            = c.GetString(CfgSsePublicURL)
	)

	// Unique ID generator
	var idGenerator = idgenerator.New(keycloakb.ComponentName, ComponentID)

	// Critical errors channel.
	var errc = make(chan error)
	go func() {
		var c = make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	// Configure log filtering
	{
		var level kit_level.Option
		var err error
		level, err = log.ConvertToLevel(logLevel)

		if err != nil {
			logger.Error(ctx, "error", err)
			return
		}

		logger = log.AllowLevel(logger, level)
	}

	// Security - Audience required
	var audienceRequired string
	{
		audienceRequired = c.GetString(CfgAudienceRequired)

		if audienceRequired == "" {
			logger.Error(ctx, "msg", "audience parameter(audience-required) cannot be empty")
			return
		}
	}

	// Security - Basic AuthN token to protect internal/event endpoint
	var eventExpectedAuthToken string
	{
		eventExpectedAuthToken = c.GetString(CfgEventBasicAuthToken)

		if eventExpectedAuthToken == "" {
			logger.Error(ctx, "msg", "password for event endpoint (event-basic-auth-token) cannot be empty")
			return
		}
	}

	var validationExpectedAuthToken string
	{
		validationExpectedAuthToken = c.GetString(CfgValidationBasicAuthToken)

		if validationExpectedAuthToken == "" {
			logger.Error(ctx, "msg", "password for validation endpoint (validation-basic-auth-token) cannot be empty")
			return
		}
	}

	// Security - allowed trustID groups
	var trustIDGroups = c.GetStringSlice(CfgTrustIDGroups)

	// Keycloak client.
	var keycloakClient *keycloakapi.Client
	{
		var err error
		keycloakClient, err = keycloakapi.New(keycloakConfig)

		if err != nil {
			logger.Error(ctx, "msg", "could not create Keycloak client", "error", err)
			return
		}
	}

	// Recaptcha secret
	if registerEnabled && recaptchaSecret == "" {
		logger.Error(ctx, "msg", "Recaptcha secret is not configured")
		return
	}

	// Keycloak adaptor for common-service library
	commonKcAdaptor := keycloakb.NewKeycloakAuthClient(keycloakClient, logger)

	// Public Keycloak URL
	var keycloakPublicURL string
	{
		urls := strings.Split(keycloakConfig.AddrTokenProvider, " ")
		keycloakPublicURL = urls[0]
	}

	var sentryClient tracking.SentryTracking
	{
		var logger = log.With(logger, "unit", "sentry")
		var err error
		sentryClient, err = tracking.NewSentry(c, "sentry")
		if err != nil {
			logger.Error(ctx, "msg", "could not create Sentry client", "error", err)
			return
		}
		defer sentryClient.Close()
	}

	var influxMetrics metrics.Metrics
	{
		var err error
		influxMetrics, err = metrics.NewMetrics(c, "influx", logger)
		if err != nil {
			logger.Error(ctx, "msg", "could not create Influx client", "error", err)
			return
		}
		defer influxMetrics.Close()
	}

	// Jaeger client.
	var tracer tracing.OpentracingClient
	{
		var logger = log.With(logger, "unit", "jaeger")
		var err error

		tracer, err = tracing.CreateJaegerClient(c, "jaeger", keycloakb.ComponentName)
		if err != nil {
			logger.Error(ctx, "msg", "could not create Jaeger tracer", "error", err)
			return
		}
		defer tracer.Close()
	}

	var eventsDBConn sqltypes.CloudtrustDB
	{
		var err error
		eventsDBConn, err = database.NewReconnectableCloudtrustDB(auditRwDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create R/W DB connection for audit events", "error", err)
			return
		}
	}

	var eventsRODBConn sqltypes.CloudtrustDB
	{
		var err error
		eventsRODBConn, err = database.NewReconnectableCloudtrustDB(auditRoDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create RO DB connection for audit events", "error", err)
			return
		}
	}

	var configurationRwDBConn sqltypes.CloudtrustDB
	{
		var err error
		configurationRwDBConn, err = database.NewReconnectableCloudtrustDB(configRwDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for configuration storage (RW)", "error", err)
			return
		}
	}

	var configurationRoDBConn sqltypes.CloudtrustDB
	{
		var err error
		configurationRoDBConn, err = database.NewReconnectableCloudtrustDB(configRoDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for configuration storage (RO)", "error", err)
			return
		}
	}

	var usersRwDBConn sqltypes.CloudtrustDB
	{
		var err error
		usersRwDBConn, err = database.NewReconnectableCloudtrustDB(usersRwDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for users (RW)", "error", err)
			return
		}
	}

	// Create OIDC token provider and validate technical user credentials
	var oidcTokenProvider toolbox.OidcTokenProvider
	{
		oidcTokenProvider = toolbox.NewOidcTokenProvider(keycloakConfig, registerRealm, registerUsername, registerPassword, registerClientID, logger)
		var _, err = oidcTokenProvider.ProvideToken(context.Background())
		if err != nil {
			logger.Warn(context.Background(), "msg", "OIDC token provider validation failed for technical user", "err", err.Error())
		}
	}

	// Health check configuration
	var healthChecker = healthcheck.NewHealthChecker(keycloakb.ComponentName, logger)
	var healthCheckCacheDuration = c.GetDuration("livenessprobe-cache-duration") * time.Millisecond
	var httpTimeout = c.GetDuration("livenessprobe-http-timeout") * time.Millisecond
	healthChecker.AddDatabase("Audit R/W", eventsDBConn, healthCheckCacheDuration)
	healthChecker.AddDatabase("Audit RO", eventsRODBConn, healthCheckCacheDuration)
	healthChecker.AddDatabase("Config R/W", configurationRwDBConn, healthCheckCacheDuration)
	healthChecker.AddDatabase("Config RO", configurationRoDBConn, healthCheckCacheDuration)
	healthChecker.AddDatabase("Users R/W", usersRwDBConn, healthCheckCacheDuration)
	healthChecker.AddHTTPEndpoint("Keycloak", keycloakConfig.AddrAPI, httpTimeout, 200, healthCheckCacheDuration)

	// Authorization Manager
	var authorizationManager security.AuthorizationManager
	{
		var authorizationLogger = log.With(logger, "svc", "authorization")

		var configurationReaderDBModule *configuration.ConfigurationReaderDBModule
		{
			configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, authorizationLogger)
		}

		var err error
		authorizationManager, err = security.NewAuthorizationManager(configurationReaderDBModule, commonKcAdaptor, authorizationLogger)

		if err != nil {
			logger.Error(ctx, "msg", "could not load authorizations", "error", err)
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
			statisticModule = event.NewStatisticModule(influxMetrics)
			statisticModule = event.MakeStatisticModuleInstrumentingMW(influxMetrics.NewHistogram("statistic_module"))(statisticModule)
			statisticModule = event.MakeStatisticModuleLoggingMW(log.With(eventLogger, "mw", "module", "unit", "statistic"))(statisticModule)
			statisticModule = event.MakeStatisticModuleTracingMW(tracer)(statisticModule)
		}

		// new module for sending the events to the DB
		var eventsDBModule database.EventsDBModule
		{
			eventsDBModule = database.NewEventsDBModule(eventsDBConn)
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

		var eventEndpoint cs.Endpoint
		{
			eventEndpoint = event.MakeEventEndpoint(muxComponent)
			eventEndpoint = middleware.MakeEndpointInstrumentingMW(influxMetrics, "event_endpoint")(eventEndpoint)
			eventEndpoint = middleware.MakeEndpointLoggingMW(log.With(eventLogger, "mw", "endpoint"))(eventEndpoint)
			eventEndpoint = tracer.MakeEndpointTracingMW("event_endpoint")(eventEndpoint)
		}

		eventEndpoints = event.Endpoints{
			Endpoint: keycloakb.LimitRate(eventEndpoint, rateLimit[RateKeyEvent]),
		}
	}

	baseEventsDBModule := database.NewEventsDBModule(eventsDBConn)

	// new module for reading events from the DB
	eventsRODBModule := keycloakb.NewEventsDBModule(eventsRODBConn)

	// Validation service.
	var validationEndpoints validation.Endpoints
	{
		var validationLogger = log.With(logger, "svc", "validation")

		// module to store validation API calls
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, validationLogger, tracer)

		// module for storing and retrieving details of the users
		var usersDBModule = keycloakb.NewUsersDBModule(usersRwDBConn, validationLogger)

		// accreditations module
		var accredsModule keycloakb.AccreditationsModule
		{
			var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, validationLogger)
			accredsModule = keycloakb.NewAccreditationsModule(keycloakClient, configurationReaderDBModule, validationLogger)
		}

		validationComponent := validation.NewComponent(registerRealm, keycloakClient, oidcTokenProvider, usersDBModule, eventsDBModule, accredsModule, validationLogger)

		var rateLimitValidation = rateLimit[RateKeyValidation]
		validationEndpoints = validation.Endpoints{
			GetUser:     prepareEndpoint(validation.MakeGetUserEndpoint(validationComponent), "get_user", influxMetrics, validationLogger, tracer, rateLimitValidation),
			UpdateUser:  prepareEndpoint(validation.MakeUpdateUserEndpoint(validationComponent), "update_user", influxMetrics, validationLogger, tracer, rateLimitValidation),
			CreateCheck: prepareEndpoint(validation.MakeCreateCheckEndpoint(validationComponent), "create_check", influxMetrics, validationLogger, tracer, rateLimitValidation),
		}
	}

	// Statistics service.
	var statisticsEndpoints statistics.Endpoints
	{
		var statisticsLogger = log.With(logger, "svc", "statistics")

		statisticsComponent := statistics.NewComponent(eventsRODBModule, keycloakClient, statisticsLogger)
		statisticsComponent = statistics.MakeAuthorizationManagementComponentMW(log.With(statisticsLogger, "mw", "endpoint"), authorizationManager)(statisticsComponent)

		var rateLimitStatistics = rateLimit[RateKeyStatistics]
		statisticsEndpoints = statistics.Endpoints{
			GetActions:                      prepareEndpoint(statistics.MakeGetActionsEndpoint(statisticsComponent), "get_actions", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetStatistics:                   prepareEndpoint(statistics.MakeGetStatisticsEndpoint(statisticsComponent), "get_statistics", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetStatisticsUsers:              prepareEndpoint(statistics.MakeGetStatisticsUsersEndpoint(statisticsComponent), "get_statistics_users", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetStatisticsAuthentications:    prepareEndpoint(statistics.MakeGetStatisticsAuthenticationsEndpoint(statisticsComponent), "get_statistics_authentications", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetStatisticsAuthenticationsLog: prepareEndpoint(statistics.MakeGetStatisticsAuthenticationsLogEndpoint(statisticsComponent), "get_statistics_authentications_log", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetStatisticsAuthenticators:     prepareEndpoint(statistics.MakeGetStatisticsAuthenticatorsEndpoint(statisticsComponent), "get_statistics_authenticators", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetMigrationReport:              prepareEndpoint(statistics.MakeGetMigrationReportEndpoint(statisticsComponent), "get_migration_report", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
		}
	}

	// Events service.
	var eventsEndpoints events.Endpoints
	{
		var eventsLogger = log.With(logger, "svc", "events")

		// module to store API calls of the back office to the DB
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, eventsLogger, tracer)

		eventsComponent := events.NewComponent(eventsRODBModule, eventsDBModule, eventsLogger)
		eventsComponent = events.MakeAuthorizationManagementComponentMW(log.With(eventsLogger, "mw", "endpoint"), authorizationManager)(eventsComponent)

		var rateLimitEvents = rateLimit[RateKeyEvents]
		eventsEndpoints = events.Endpoints{
			GetActions:       prepareEndpoint(events.MakeGetActionsEndpoint(eventsComponent), "get_actions", influxMetrics, eventsLogger, tracer, rateLimitEvents),
			GetEvents:        prepareEndpoint(events.MakeGetEventsEndpoint(eventsComponent), "get_events", influxMetrics, eventsLogger, tracer, rateLimitEvents),
			GetEventsSummary: prepareEndpoint(events.MakeGetEventsSummaryEndpoint(eventsComponent), "get_events_summary", influxMetrics, eventsLogger, tracer, rateLimitEvents),
			GetUserEvents:    prepareEndpoint(events.MakeGetUserEventsEndpoint(eventsComponent), "get_user_events", influxMetrics, eventsLogger, tracer, rateLimitEvents),
		}
	}

	// Management service.
	var managementEndpoints = management.Endpoints{}
	{
		var managementLogger = log.With(logger, "svc", "management")

		// module to store API calls of the back office to the DB
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, managementLogger, tracer)

		// module for storing and retrieving the custom configuration
		var configDBModule = createConfigurationDBModule(configurationRwDBConn, influxMetrics, managementLogger)

		var keycloakComponent management.Component
		{
			keycloakComponent = management.NewComponent(keycloakClient, eventsDBModule, configDBModule, trustIDGroups, managementLogger)
			keycloakComponent = management.MakeAuthorizationManagementComponentMW(log.With(managementLogger, "mw", "endpoint"), authorizationManager)(keycloakComponent)
		}

		var rateLimitMgmt = rateLimit[RateKeyManagement]
		managementEndpoints = management.Endpoints{
			GetActions: prepareEndpoint(management.MakeGetActionsEndpoint(keycloakComponent), "get_actions_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetRealms: prepareEndpoint(management.MakeGetRealmsEndpoint(keycloakComponent), "realms_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRealm:  prepareEndpoint(management.MakeGetRealmEndpoint(keycloakComponent), "realm_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetClients:         prepareEndpoint(management.MakeGetClientsEndpoint(keycloakComponent), "get_clients_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetClient:          prepareEndpoint(management.MakeGetClientEndpoint(keycloakComponent), "get_client_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRequiredActions: prepareEndpoint(management.MakeGetRequiredActionsEndpoint(keycloakComponent), "get_required-actions_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			CreateUser:                prepareEndpoint(management.MakeCreateUserEndpoint(keycloakComponent), "create_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUser:                   prepareEndpoint(management.MakeGetUserEndpoint(keycloakComponent), "get_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UpdateUser:                prepareEndpoint(management.MakeUpdateUserEndpoint(keycloakComponent), "update_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteUser:                prepareEndpoint(management.MakeDeleteUserEndpoint(keycloakComponent), "delete_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUsers:                  prepareEndpoint(management.MakeGetUsersEndpoint(keycloakComponent), "get_users_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUserAccountStatus:      prepareEndpoint(management.MakeGetUserAccountStatusEndpoint(keycloakComponent), "get_user_accountstatus", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetGroupsOfUser:           prepareEndpoint(management.MakeGetGroupsOfUserEndpoint(keycloakComponent), "get_user_groups", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			AddGroupToUser:            prepareEndpoint(management.MakeAddGroupToUserEndpoint(keycloakComponent), "add_user_group", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteGroupForUser:        prepareEndpoint(management.MakeDeleteGroupForUserEndpoint(keycloakComponent), "del_user_group", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetAvailableTrustIDGroups: prepareEndpoint(management.MakeGetAvailableTrustIDGroupsEndpoint(keycloakComponent), "get_available_trustid_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetTrustIDGroupsOfUser:    prepareEndpoint(management.MakeGetTrustIDGroupsOfUserEndpoint(keycloakComponent), "get_user_trustid_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			SetTrustIDGroupsToUser:    prepareEndpoint(management.MakeSetTrustIDGroupsToUserEndpoint(keycloakComponent), "set_user_trustid_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRolesOfUser:            prepareEndpoint(management.MakeGetRolesOfUserEndpoint(keycloakComponent), "get_user_roles", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetRoles: prepareEndpoint(management.MakeGetRolesEndpoint(keycloakComponent), "get_roles_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRole:  prepareEndpoint(management.MakeGetRoleEndpoint(keycloakComponent), "get_role_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetGroups:            prepareEndpoint(management.MakeGetGroupsEndpoint(keycloakComponent), "get_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			CreateGroup:          prepareEndpoint(management.MakeCreateGroupEndpoint(keycloakComponent), "create_group_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteGroup:          prepareEndpoint(management.MakeDeleteGroupEndpoint(keycloakComponent), "delete_group_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetAuthorizations:    prepareEndpoint(management.MakeGetAuthorizationsEndpoint(keycloakComponent), "get_authorizations_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UpdateAuthorizations: prepareEndpoint(management.MakeUpdateAuthorizationsEndpoint(keycloakComponent), "update_authorizations_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetClientRoles:       prepareEndpoint(management.MakeGetClientRolesEndpoint(keycloakComponent), "get_client_roles_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			CreateClientRole:     prepareEndpoint(management.MakeCreateClientRoleEndpoint(keycloakComponent), "create_client_role_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetClientRoleForUser: prepareEndpoint(management.MakeGetClientRolesForUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			AddClientRoleToUser:  prepareEndpoint(management.MakeAddClientRolesToUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			ResetPassword:            prepareEndpointWithoutLogging(management.MakeResetPasswordEndpoint(keycloakComponent), "reset_password_endpoint", influxMetrics, tracer, rateLimitMgmt),
			ExecuteActionsEmail:      prepareEndpoint(management.MakeExecuteActionsEmailEndpoint(keycloakComponent), "execute_actions_email_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			SendReminderEmail:        prepareEndpoint(management.MakeSendReminderEmailEndpoint(keycloakComponent), "send_reminder_email_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			SendNewEnrolmentCode:     prepareEndpoint(management.MakeSendNewEnrolmentCodeEndpoint(keycloakComponent), "send_new_enrolment_code_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			ResetSmsCounter:          prepareEndpoint(management.MakeResetSmsCounterEndpoint(keycloakComponent), "reset_sms_counter_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			CreateRecoveryCode:       prepareEndpoint(management.MakeCreateRecoveryCodeEndpoint(keycloakComponent), "create_recovery_code_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetCredentialsForUser:    prepareEndpoint(management.MakeGetCredentialsForUserEndpoint(keycloakComponent), "get_credentials_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteCredentialsForUser: prepareEndpoint(management.MakeDeleteCredentialsForUserEndpoint(keycloakComponent), "delete_credentials_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			ClearUserLoginFailures:   prepareEndpoint(management.MakeClearUserLoginFailures(keycloakComponent), "clear_user_login_failures_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetAttackDetectionStatus: prepareEndpoint(management.MakeGetAttackDetectionStatus(keycloakComponent), "get_attack_detection_status_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetRealmCustomConfiguration:    prepareEndpoint(management.MakeGetRealmCustomConfigurationEndpoint(keycloakComponent), "get_realm_custom_config_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UpdateRealmCustomConfiguration: prepareEndpoint(management.MakeUpdateRealmCustomConfigurationEndpoint(keycloakComponent), "update_realm_custom_config_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRealmAdminConfiguration:     prepareEndpoint(management.MakeGetRealmAdminConfigurationEndpoint(keycloakComponent), "get_realm_admin_config_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UpdateRealmAdminConfiguration:  prepareEndpoint(management.MakeUpdateRealmAdminConfigurationEndpoint(keycloakComponent), "update_realm_admin_config_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetRealmBackOfficeConfiguration:     prepareEndpoint(management.MakeGetRealmBackOfficeConfigurationEndpoint(keycloakComponent), "get_realm_back_office_config_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UpdateRealmBackOfficeConfiguration:  prepareEndpoint(management.MakeUpdateRealmBackOfficeConfigurationEndpoint(keycloakComponent), "update_realm_back_office_config_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUserRealmBackOfficeConfiguration: prepareEndpoint(management.MakeGetUserRealmBackOfficeConfigurationEndpoint(keycloakComponent), "get_user_realm_back_office_config_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			LinkShadowUser: prepareEndpoint(management.MakeLinkShadowUserEndpoint(keycloakComponent), "link_shadow_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
		}
	}

	// Account service.
	var accountEndpoints account.Endpoints
	{
		var accountLogger = log.With(logger, "svc", "account")

		// Configure events db module
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, accountLogger, tracer)

		// module for retrieving the custom configuration
		var configDBModule keycloakb.ConfigurationDBModule
		{
			configDBModule = keycloakb.NewConfigurationDBModule(configurationRoDBConn, accountLogger)
			configDBModule = keycloakb.MakeConfigurationDBModuleInstrumentingMW(influxMetrics.NewHistogram("configDB_module"))(configDBModule)
		}

		// module for storing and retrieving details of the self-registered users
		var usersDBModule = keycloakb.NewUsersDBModule(usersRwDBConn, accountLogger)

		// new module for account service
		accountComponent := account.NewComponent(keycloakClient.AccountClient(), eventsDBModule, configDBModule, usersDBModule, accountLogger)
		accountComponent = account.MakeAuthorizationAccountComponentMW(log.With(accountLogger, "mw", "endpoint"), configDBModule)(accountComponent)

		var rateLimitAccount = rateLimit[RateKeyAccount]
		accountEndpoints = account.Endpoints{
			GetAccount:                prepareEndpoint(account.MakeGetAccountEndpoint(accountComponent), "get_account", influxMetrics, accountLogger, tracer, rateLimitAccount),
			UpdateAccount:             prepareEndpoint(account.MakeUpdateAccountEndpoint(accountComponent), "update_account", influxMetrics, accountLogger, tracer, rateLimitAccount),
			DeleteAccount:             prepareEndpoint(account.MakeDeleteAccountEndpoint(accountComponent), "delete_account", influxMetrics, accountLogger, tracer, rateLimitAccount),
			UpdatePassword:            prepareEndpointWithoutLogging(account.MakeUpdatePasswordEndpoint(accountComponent), "update_password", influxMetrics, tracer, rateLimitAccount),
			GetCredentials:            prepareEndpoint(account.MakeGetCredentialsEndpoint(accountComponent), "get_credentials", influxMetrics, accountLogger, tracer, rateLimitAccount),
			GetCredentialRegistrators: prepareEndpoint(account.MakeGetCredentialRegistratorsEndpoint(accountComponent), "get_credential_registrators", influxMetrics, accountLogger, tracer, rateLimitAccount),
			DeleteCredential:          prepareEndpoint(account.MakeDeleteCredentialEndpoint(accountComponent), "delete_credential", influxMetrics, accountLogger, tracer, rateLimitAccount),
			UpdateLabelCredential:     prepareEndpoint(account.MakeUpdateLabelCredentialEndpoint(accountComponent), "update_label_credential", influxMetrics, accountLogger, tracer, rateLimitAccount),
			MoveCredential:            prepareEndpoint(account.MakeMoveCredentialEndpoint(accountComponent), "move_credential", influxMetrics, accountLogger, tracer, rateLimitAccount),
			GetConfiguration:          prepareEndpoint(account.MakeGetConfigurationEndpoint(accountComponent), "get_configuration", influxMetrics, accountLogger, tracer, rateLimitAccount),
			SendVerifyEmail:           prepareEndpoint(account.MakeSendVerifyEmailEndpoint(accountComponent), "send_verify_email", influxMetrics, accountLogger, tracer, rateLimitAccount),
			SendVerifyPhoneNumber:     prepareEndpoint(account.MakeSendVerifyPhoneNumberEndpoint(accountComponent), "send_verify_phone_number", influxMetrics, accountLogger, tracer, rateLimitAccount),
		}
	}

	// Register service.
	var registerEndpoints register.Endpoints
	{
		var registerLogger = log.With(logger, "svc", "register")

		// Configure events db module
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, registerLogger, tracer)

		// module for storing and retrieving the custom configuration
		var configDBModule = createConfigurationDBModule(configurationRwDBConn, influxMetrics, registerLogger)

		// module for storing and retrieving details of the self-registered users
		var usersDBModule = keycloakb.NewUsersDBModule(usersRwDBConn, registerLogger)

		// new module for register service
		registerComponent := register.NewComponent(keycloakPublicURL, registerRealm, ssePublicURL, registerEnduserClientID, keycloakClient, oidcTokenProvider, usersDBModule, configDBModule, eventsDBModule, registerLogger)
		registerComponent = register.MakeAuthorizationRegisterComponentMW(log.With(registerLogger, "mw", "endpoint"))(registerComponent)

		var rateLimitRegister = rateLimit[RateKeyRegister]
		registerEndpoints = register.Endpoints{
			RegisterUser:     prepareEndpoint(register.MakeRegisterUserEndpoint(registerComponent), "register_user", influxMetrics, registerLogger, tracer, rateLimitRegister),
			GetConfiguration: prepareEndpoint(register.MakeGetConfigurationEndpoint(registerComponent), "get_configuration", influxMetrics, registerLogger, tracer, rateLimitRegister),
		}
	}

	// KYC service.
	var kycEndpoints kyc.Endpoints
	{
		var kycLogger = log.With(logger, "svc", "kyc")

		// Configure events db module
		eventsDBModule := configureEventsDbModule(baseEventsDBModule, influxMetrics, kycLogger, tracer)

		// module for storing and retrieving details of the users
		var usersDBModule = keycloakb.NewUsersDBModule(usersRwDBConn, kycLogger)

		// accreditations module
		var accredsModule keycloakb.AccreditationsModule
		{
			var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, kycLogger)
			accredsModule = keycloakb.NewAccreditationsModule(keycloakClient, configurationReaderDBModule, kycLogger)
		}

		// new module for KYC service
		kycComponent := kyc.NewComponent(registerRealm, keycloakClient, usersDBModule, eventsDBModule, accredsModule, kycLogger)
		kycComponent = kyc.MakeAuthorizationRegisterComponentMW(registerRealm, log.With(kycLogger, "mw", "endpoint"), authorizationManager)(kycComponent)

		var rateLimitKyc = rateLimit[RateKeyKYC]
		kycEndpoints = kyc.Endpoints{
			GetActions:        prepareEndpoint(kyc.MakeGetActionsEndpoint(kycComponent), "register_get_actions", influxMetrics, kycLogger, tracer, rateLimitKyc),
			GetUser:           prepareEndpoint(kyc.MakeGetUserEndpoint(kycComponent), "get_user", influxMetrics, kycLogger, tracer, rateLimitKyc),
			GetUserByUsername: prepareEndpoint(kyc.MakeGetUserByUsernameEndpoint(kycComponent), "get_user_by_username", influxMetrics, kycLogger, tracer, rateLimitKyc),
			ValidateUser:      prepareEndpoint(kyc.MakeValidateUserEndpoint(kycComponent), "validate_user", influxMetrics, kycLogger, tracer, rateLimitKyc),
		}
	}

	// Tools for endpoint middleware
	var idRetriever = keycloakb.NewRealmIDRetriever(keycloakClient)
	var configurationReaderDBModule *configuration.ConfigurationReaderDBModule
	{
		configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, logger)
	}

	// Export configuration
	var exportModule = export.NewModule(keycloakClient, logger)
	var cfgStorageModue = export.NewConfigStorageModule(eventsDBConn)

	var exportComponent = export.NewComponent(keycloakb.ComponentName, keycloakb.Version, logger, exportModule, cfgStorageModue)
	var exportEndpoint = export.MakeExportEndpoint(exportComponent)
	var exportSaveAndExportEndpoint = export.MakeStoreAndExportEndpoint(exportComponent)

	errorhandler.SetEmitter(keycloakb.ComponentName)

	// HTTP Internal Call Server (Event reception from Keycloak & Export API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrInternal)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", commonhttp.MakeVersionHandler(keycloakb.ComponentName, ComponentID, keycloakb.Version, Environment, GitCommit))
		route.Handle("/health/check", healthChecker.MakeHandler())

		// Event.
		var eventSubroute = route.PathPrefix("/event").Subrouter()

		var eventHandler http.Handler
		{
			eventHandler = event.MakeHTTPEventHandler(eventEndpoints.Endpoint, logger)
			eventHandler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, keycloakb.ComponentName, ComponentID)(eventHandler)
			eventHandler = tracer.MakeHTTPTracingMW(keycloakb.ComponentName, "http_server_event")(eventHandler)
			eventHandler = middleware.MakeHTTPBasicAuthenticationMW(eventExpectedAuthToken, logger)(eventHandler)
		}
		eventSubroute.Handle("/receiver", eventHandler)

		// Export.
		route.Handle("/export", export.MakeHTTPExportHandler(exportEndpoint)).Methods("GET")
		route.Handle("/export", export.MakeHTTPExportHandler(exportSaveAndExportEndpoint)).Methods("POST")

		// Validation
		var getUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.GetUser)
		var updateUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.UpdateUser)
		var createCheckHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.CreateCheck)

		var validationSubroute = route.PathPrefix("/validation").Subrouter()

		validationSubroute.Path("/users/{userID}").Methods("GET").Handler(getUserHandler)
		validationSubroute.Path("/users/{userID}").Methods("POST").Handler(updateUserHandler)
		validationSubroute.Path("/users/{userID}/checks").Methods("POST").Handler(createCheckHandler)

		// Debug.
		if pprofRouteEnabled {
			var debugSubroute = route.PathPrefix("/debug").Subrouter()
			debugSubroute.HandleFunc("/pprof/", http.HandlerFunc(pprof.Index))
			debugSubroute.HandleFunc("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
			debugSubroute.HandleFunc("/pprof/profile", http.HandlerFunc(pprof.Profile))
			debugSubroute.HandleFunc("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
			debugSubroute.HandleFunc("/pprof/trace", http.HandlerFunc(pprof.Trace))
		}

		var handler http.Handler = route
		if accessLogsEnabled {
			handler = commonhttp.MakeAccessLogHandler(accessLogger, route)
		}

		errc <- http.ListenAndServe(httpAddrInternal, handler)
	}()

	// HTTP Management Server (Backoffice API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrManagement)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", http.HandlerFunc(commonhttp.MakeVersionHandler(keycloakb.ComponentName, ComponentID, keycloakb.Version, Environment, GitCommit)))
		route.Handle("/health/check", healthChecker.MakeHandler())

		// Rights
		var rightsHandler = configureRightsHandler(keycloakb.ComponentName, ComponentID, idGenerator, authorizationManager, keycloakClient, audienceRequired, tracer, logger)
		route.Path("/rights").Methods("GET").Handler(rightsHandler)

		// Statistics
		var getStatisticsActionsHandler = configureStatisiticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetActions)
		var getStatisticsHandler = configureStatisiticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatistics)
		var getStatisticsUsersHandler = configureStatisiticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsUsers)
		var getStatisticsAuthenticatorsHandler = configureStatisiticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsAuthenticators)
		var getStatisticsAuthenticationsHandler = configureStatisiticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsAuthentications)
		var getStatisticsAuthenticationsLogHandler = configureStatisiticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsAuthenticationsLog)
		var getMigrationReportHandler = configureStatisiticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetMigrationReport)

		route.Path("/statistics/actions").Methods("GET").Handler(getStatisticsActionsHandler)
		route.Path("/statistics/realms/{realm}").Methods("GET").Handler(getStatisticsHandler)
		route.Path("/statistics/realms/{realm}/users").Methods("GET").Handler(getStatisticsUsersHandler)
		route.Path("/statistics/realms/{realm}/authenticators").Methods("GET").Handler(getStatisticsAuthenticatorsHandler)
		route.Path("/statistics/realms/{realm}/authentications-graph").Methods("GET").Handler(getStatisticsAuthenticationsHandler)
		route.Path("/statistics/realms/{realm}/authentications-log").Methods("GET").Handler(getStatisticsAuthenticationsLogHandler)
		route.Path("/statistics/realms/{realm}/migration").Methods("GET").Handler(getMigrationReportHandler)

		// Events
		var getEventsActionsHandler = configureEventsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(eventsEndpoints.GetActions)
		var getEventsHandler = configureEventsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(eventsEndpoints.GetEvents)
		var getEventsSummaryHandler = configureEventsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(eventsEndpoints.GetEventsSummary)
		var getUserEventsHandler = configureEventsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(eventsEndpoints.GetUserEvents)

		route.Path("/events").Methods("GET").Handler(getEventsHandler)
		route.Path("/events/actions").Methods("GET").Handler(getEventsActionsHandler)
		route.Path("/events/summary").Methods("GET").Handler(getEventsSummaryHandler)
		route.Path("/events/realms/{realm}/users/{userID}/events").Methods("GET").Handler(getUserEventsHandler)

		// Management
		var managementSubroute = route.PathPrefix("/management").Subrouter()

		var getRealmsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealms)
		var getRealmHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealm)

		var getClientsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClients)
		var getClientHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClient)

		var getRequiredActionsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRequiredActions)

		var createUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateUser)
		var getUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUser)
		var updateUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UpdateUser)
		var deleteUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteUser)
		var getUsersHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUsers)
		var getRolesForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRolesOfUser)
		var getGroupsForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetGroupsOfUser)
		var addGroupToUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.AddGroupToUser)
		var deleteGroupForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteGroupForUser)
		var getUserAccountStatusHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUserAccountStatus)
		var getAvailableTrustIDGroupsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetAvailableTrustIDGroups)
		var getTrustIDGroupsOfUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetTrustIDGroupsOfUser)
		var setTrustIDGroupsToUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SetTrustIDGroupsToUser)

		var getClientRoleForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClientRoleForUser)
		var addClientRoleToUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.AddClientRoleToUser)

		var getRolesHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRoles)
		var getRoleHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRole)
		var getClientRolesHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetClientRoles)
		var createClientRolesHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateClientRole)

		var getGroupsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetGroups)
		var createGroupHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateGroup)
		var deleteGroupHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteGroup)
		var getAuthorizationsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetAuthorizations)
		var updateAuthorizationsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UpdateAuthorizations)
		var getManagementActionsHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetActions)

		var resetPasswordHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ResetPassword)
		var executeActionsEmailHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ExecuteActionsEmail)
		var sendNewEnrolmentCodeHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SendNewEnrolmentCode)
		var sendReminderEmailHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SendReminderEmail)
		var resetSmsCounterHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ResetSmsCounter)
		var createRecoveryCodeHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateRecoveryCode)

		var getCredentialsForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetCredentialsForUser)
		var deleteCredentialsForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteCredentialsForUser)
		var clearUserLoginFailuresHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ClearUserLoginFailures)
		var getAttackDetectionStatusHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetAttackDetectionStatus)

		var getRealmCustomConfigurationHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealmCustomConfiguration)
		var updateRealmCustomConfigurationHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UpdateRealmCustomConfiguration)
		var getRealmAdminConfigurationHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealmAdminConfiguration)
		var updateRealmAdminConfigurationHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UpdateRealmAdminConfiguration)

		var getRealmBackOfficeConfigurationHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRealmBackOfficeConfiguration)
		var updateRealmBackOfficeConfigurationHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UpdateRealmBackOfficeConfiguration)
		var getUserRealmBackOfficeConfigurationHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUserRealmBackOfficeConfiguration)

		var linkShadowUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.LinkShadowUser)

		// KYC handlers
		var kycGetActionsHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, idRetriever, configurationReaderDBModule, false, logger)(kycEndpoints.GetActions)
		var kycGetUserHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, idRetriever, configurationReaderDBModule, true, logger)(kycEndpoints.GetUser)
		var kycGetUserByUsernameHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, idRetriever, configurationReaderDBModule, true, logger)(kycEndpoints.GetUserByUsername)
		var kycValidateUserHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, idRetriever, configurationReaderDBModule, true, logger)(kycEndpoints.ValidateUser)

		// actions
		managementSubroute.Path("/actions").Methods("GET").Handler(getManagementActionsHandler)

		// realms
		managementSubroute.Path("/realms").Methods("GET").Handler(getRealmsHandler)
		managementSubroute.Path("/realms/{realm}").Methods("GET").Handler(getRealmHandler)

		// clients
		managementSubroute.Path("/realms/{realm}/clients").Methods("GET").Handler(getClientsHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}").Methods("GET").Handler(getClientHandler)

		// required-actions
		managementSubroute.Path("/realms/{realm}/required-actions").Methods("GET").Handler(getRequiredActionsHandler)

		// available trust id groups
		managementSubroute.Path("/realms/{realm}/trustIdGroups").Methods("GET").Handler(getAvailableTrustIDGroupsHandler)

		// users
		managementSubroute.Path("/realms/{realm}/users").Methods("GET").Handler(getUsersHandler)
		managementSubroute.Path("/realms/{realm}/users").Methods("POST").Handler(createUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("GET").Handler(getUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("PUT").Handler(updateUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("DELETE").Handler(deleteUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/groups").Methods("GET").Handler(getGroupsForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/groups/{groupID}").Methods("POST").Handler(addGroupToUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/groups/{groupID}").Methods("DELETE").Handler(deleteGroupForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/roles").Methods("GET").Handler(getRolesForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/status").Methods("GET").Handler(getUserAccountStatusHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/trustIdGroups").Methods("GET").Handler(getTrustIDGroupsOfUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/trustIdGroups").Methods("PUT").Handler(setTrustIDGroupsToUserHandler)

		// role mappings
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("GET").Handler(getClientRoleForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("POST").Handler(addClientRoleToUserHandler)

		managementSubroute.Path("/realms/{realm}/users/{userID}/reset-password").Methods("PUT").Handler(resetPasswordHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/execute-actions-email").Methods("PUT").Handler(executeActionsEmailHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-new-enrolment-code").Methods("POST").Handler(sendNewEnrolmentCodeHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-reminder-email").Methods("POST").Handler(sendReminderEmailHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/reset-sms-counter").Methods("PUT").Handler(resetSmsCounterHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/recovery-code").Methods("POST").Handler(createRecoveryCodeHandler)

		// Credentials
		managementSubroute.Path("/realms/{realm}/users/{userID}/credentials").Methods("GET").Handler(getCredentialsForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/credentials/{credentialID}").Methods("DELETE").Handler(deleteCredentialsForUserHandler)

		managementSubroute.Path("/realms/{realm}/users/{userID}/clear-login-failures").Methods("DELETE").Handler(clearUserLoginFailuresHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/attack-detection-status").Methods("GET").Handler(getAttackDetectionStatusHandler)

		// roles
		managementSubroute.Path("/realms/{realm}/roles").Methods("GET").Handler(getRolesHandler)
		managementSubroute.Path("/realms/{realm}/roles-by-id/{roleID}").Methods("GET").Handler(getRoleHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}/roles").Methods("GET").Handler(getClientRolesHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}/roles").Methods("POST").Handler(createClientRolesHandler)

		// groups
		managementSubroute.Path("/realms/{realm}/groups").Methods("GET").Handler(getGroupsHandler)
		managementSubroute.Path("/realms/{realm}/groups").Methods("POST").Handler(createGroupHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}").Methods("DELETE").Handler(deleteGroupHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}/authorizations").Methods("GET").Handler(getAuthorizationsHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}/authorizations").Methods("PUT").Handler(updateAuthorizationsHandler)

		// custom configuration per realm
		managementSubroute.Path("/realms/{realm}/configuration").Methods("GET").Handler(getRealmCustomConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/configuration").Methods("PUT").Handler(updateRealmCustomConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/admin-configuration").Methods("GET").Handler(getRealmAdminConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/admin-configuration").Methods("PUT").Handler(updateRealmAdminConfigurationHandler)

		managementSubroute.Path("/realms/{realm}/backoffice-configuration/groups").Methods("GET").Handler(getRealmBackOfficeConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/backoffice-configuration/groups").Methods("PUT").Handler(updateRealmBackOfficeConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/backoffice-configuration").Methods("GET").Handler(getUserRealmBackOfficeConfigurationHandler)

		// brokering - shadow users
		managementSubroute.Path("/realms/{realm}/users/{userID}/federated-identity/{provider}").Methods("POST").Handler(linkShadowUserHandler)

		// KYC methods
		route.Path("/kyc/actions").Methods("GET").Handler(kycGetActionsHandler)
		route.Path("/kyc/users").Methods("GET").Handler(kycGetUserByUsernameHandler)
		route.Path("/kyc/users/{userId}").Methods("GET").Handler(kycGetUserHandler)
		route.Path("/kyc/users/{userId}").Methods("PUT").Handler(kycValidateUserHandler)

		var handler http.Handler = route

		if accessLogsEnabled {
			handler = commonhttp.MakeAccessLogHandler(accessLogger, handler)
		}

		c := cors.New(corsOptions)
		handler = c.Handler(handler)

		errc <- http.ListenAndServe(httpAddrManagement, handler)

	}()

	// HTTP Self-service Server (Account API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrAccount)

		var route = mux.NewRouter()

		// Version.
		route.Handle("/", http.HandlerFunc(commonhttp.MakeVersionHandler(keycloakb.ComponentName, ComponentID, keycloakb.Version, Environment, GitCommit)))
		route.Handle("/health/check", healthChecker.MakeHandler())

		// Account
		var updatePasswordHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.UpdatePassword)
		var getCredentialsHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.GetCredentials)
		var getCredentialRegistratorsHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.GetCredentialRegistrators)
		var deleteCredentialHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.DeleteCredential)
		var updateLabelCredentialHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.UpdateLabelCredential)
		var moveCredentialHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.MoveCredential)
		var getAccountHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.GetAccount)
		var updateAccountHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.UpdateAccount)
		var deleteAccountHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.DeleteAccount)
		var getConfigurationHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.GetConfiguration)
		var sendVerifyEmailHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.SendVerifyEmail)
		var sendVerifyPhoneNumberHandler = configureAccountHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(accountEndpoints.SendVerifyPhoneNumber)

		route.Path("/account").Methods("GET").Handler(getAccountHandler)
		route.Path("/account").Methods("POST").Handler(updateAccountHandler)
		route.Path("/account").Methods("DELETE").Handler(deleteAccountHandler)

		route.Path("/account/configuration").Methods("GET").Handler(getConfigurationHandler)

		route.Path("/account/credentials").Methods("GET").Handler(getCredentialsHandler)
		route.Path("/account/credentials/password").Methods("POST").Handler(updatePasswordHandler)
		route.Path("/account/credentials/registrators").Methods("GET").Handler(getCredentialRegistratorsHandler)
		route.Path("/account/credentials/{credentialID}").Methods("DELETE").Handler(deleteCredentialHandler)
		route.Path("/account/credentials/{credentialID}").Methods("PUT").Handler(updateLabelCredentialHandler)
		route.Path("/account/credentials/{credentialID}/after/{previousCredentialID}").Methods("POST").Handler(moveCredentialHandler)

		route.Path("/account/verify-email").Methods("PUT").Handler(sendVerifyEmailHandler)
		route.Path("/account/verify-phone-number").Methods("PUT").Handler(sendVerifyPhoneNumberHandler)

		var handler http.Handler = route

		if accessLogsEnabled {
			handler = commonhttp.MakeAccessLogHandler(accessLogger, handler)
		}

		c := cors.New(corsOptions)
		handler = c.Handler(handler)

		errc <- http.ListenAndServe(httpAddrAccount, handler)
	}()

	// HTTP register Server (Register API).
	if registerEnabled {
		go func() {
			var logger = log.With(logger, "transport", "http")
			logger.Info(ctx, "addr", httpAddrRegister)

			var route = mux.NewRouter()

			// Version.
			route.Handle("/", http.HandlerFunc(commonhttp.MakeVersionHandler(keycloakb.ComponentName, ComponentID, keycloakb.Version, Environment, GitCommit)))
			route.Handle("/health/check", healthChecker.MakeHandler())

			// Handler with recaptcha token
			var registerUserHandler = configureRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, recaptchaURL, recaptchaSecret, tracer, logger)(registerEndpoints.RegisterUser)

			// Configuration
			var getConfigurationHandler = configurePublicRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, tracer, logger)(registerEndpoints.GetConfiguration)

			// Register
			route.Path("/register/user").Methods("POST").Handler(registerUserHandler)
			route.Path("/register/config").Methods("GET").Handler(getConfigurationHandler)

			var handler http.Handler = route

			if accessLogsEnabled {
				handler = commonhttp.MakeAccessLogHandler(accessLogger, handler)
			}

			c := cors.New(corsOptions)
			handler = c.Handler(handler)

			errc <- http.ListenAndServe(httpAddrRegister, handler)
		}()
	}

	// Influx writing.
	go func() {
		var tic = time.NewTicker(influxWriteInterval)
		defer tic.Stop()
		influxMetrics.WriteLoop(tic.C)
	}()

	logger.Info(ctx, "msg", "Started")
	logger.Error(ctx, "error", <-errc)
}

func config(ctx context.Context, logger log.Logger) *viper.Viper {
	logger.Info(ctx, "msg", "load configuration and command args")

	var v = viper.New()

	// Component default.
	v.SetDefault(CfgConfigFile, "./configs/keycloak_bridge.yml")

	// Log level
	v.SetDefault(CfgLogLevel, "info")

	// Access Logs
	v.SetDefault(CfgAccessLogsEnabled, true)

	// Publishing
	v.SetDefault(CfgHTTPAddrInternal, defaultPublishingIP+":8888")
	v.SetDefault(CfgHTTPAddrManagement, defaultPublishingIP+":8877")
	v.SetDefault(CfgHTTPAddrAccount, defaultPublishingIP+":8866")
	v.SetDefault(CfgHTTPAddrRegister, defaultPublishingIP+":8855")

	// Security - Audience check
	v.SetDefault(CfgAudienceRequired, "")
	v.SetDefault(CfgEventBasicAuthToken, "")
	v.SetDefault(CfgTrustIDGroups,
		[]string{
			"l1_support_manager",
			"l1_support_agent",
			"product_administrator",
			"registration_officer",
			"papercard_administrator",
			"technical",
			"end_user"})
	v.SetDefault(CfgValidationBasicAuthToken, "")

	// CORS configuration
	v.SetDefault(CfgAllowedOrigins, []string{})
	v.SetDefault(CfgAllowedMethods, []string{})
	v.SetDefault(CfgAllowCredentials, true)
	v.SetDefault(CfgAllowedHeaders, []string{})
	v.SetDefault(CfgExposedHeaders, []string{})
	v.SetDefault(CfgDebug, false)

	// Keycloak default.
	v.SetDefault(CfgAddrAPI, "http://127.0.0.1:8080")
	v.SetDefault(CfgAddrTokenProvider, "http://127.0.0.1:8080 http://localhost:8080")
	v.SetDefault(CfgTimeout, "5s")

	// Storage events in DB (read/write)
	v.SetDefault(CfgAuditRwDbParams+"-enabled", false)
	database.ConfigureDbDefault(v, CfgAuditRwDbParams, "CT_BRIDGE_DB_AUDIT_RW_USERNAME", "CT_BRIDGE_DB_AUDIT_RW_PASSWORD")

	// Storage events in DB (read only)
	database.ConfigureDbDefault(v, CfgAuditRoDbParams, "CT_BRIDGE_DB_AUDIT_RO_USERNAME", "CT_BRIDGE_DB_AUDIT_RO_PASSWORD")

	//Storage custom configuration in DB (read/write)
	v.SetDefault(CfgConfigRwDbParams+"-enabled", true)
	database.ConfigureDbDefault(v, CfgConfigRwDbParams, "CT_BRIDGE_DB_CONFIG_RW_USERNAME", "CT_BRIDGE_DB_CONFIG_RW_PASSWORD")

	v.SetDefault(CfgConfigRwDbParams+"-migration", false)
	v.SetDefault(CfgConfigRwDbParams+"-migration-version", "")

	//Storage custom configuration in DB (read only)
	v.SetDefault(CfgConfigRoDbParams+"-enabled", true)
	database.ConfigureDbDefault(v, CfgConfigRoDbParams, "CT_BRIDGE_DB_CONFIG_RO_USERNAME", "CT_BRIDGE_DB_CONFIG_RO_PASSWORD")

	v.SetDefault(CfgConfigRoDbParams+"-migration", false)
	v.SetDefault(CfgConfigRoDbParams+"-migration-version", "")

	//Storage users in DB (read/write)
	v.SetDefault(CfgUsersRwDbParams+"-enabled", true)
	database.ConfigureDbDefault(v, CfgUsersRwDbParams, "CT_BRIDGE_DB_USERS_RW_USERNAME", "CT_BRIDGE_DB_USERS_RW_PASSWORD")

	v.SetDefault(CfgUsersRwDbParams+"-migration", false)
	v.SetDefault(CfgUsersRwDbParams+"-migration-version", "")

	// Rate limiting (in requests/second)
	v.SetDefault(CfgRateKeyValidation, 1000)
	v.SetDefault(CfgRateKeyEvent, 1000)
	v.SetDefault(CfgRateKeyAccount, 1000)
	v.SetDefault(CfgRateKeyManagement, 1000)
	v.SetDefault(CfgRateKeyStatistics, 1000)
	v.SetDefault(CfgRateKeyEvents, 1000)
	v.SetDefault(CfgRateKeyRegister, 1000)
	v.SetDefault(CfgRateKeyKYC, 1000)

	// Influx DB client default.
	v.SetDefault("influx", false)
	v.SetDefault("influx-host-port", "")
	v.SetDefault("influx-username", "")
	v.SetDefault("influx-password", "")
	v.SetDefault("influx-database", "")
	v.SetDefault("influx-precision", "")
	v.SetDefault("influx-retention-policy", "")
	v.SetDefault("influx-write-consistency", "")
	v.SetDefault(CfgInfluxWriteInterval, "1s")

	// Sentry client default.
	v.SetDefault("sentry", false)
	v.SetDefault(CfgSentryDsn, "")

	// Jaeger tracing default.
	v.SetDefault("jaeger", false)
	v.SetDefault("jaeger-sampler-type", "")
	v.SetDefault("jaeger-sampler-param", 0)
	v.SetDefault("jaeger-sampler-host-port", "")
	v.SetDefault("jaeger-reporter-logspan", false)
	v.SetDefault("jaeger-write-interval", "1s")

	// Debug routes enabled.
	v.SetDefault(CfgPprofRouteEnabled, true)

	// Liveness probe
	v.SetDefault("livenessprobe-http-timeout", 900)
	v.SetDefault("livenessprobe-cache-duration", 500)

	// Register parameters
	v.SetDefault(CfgRegisterEnabled, false)
	v.SetDefault(CfgRegisterRealm, "trustid")
	v.SetDefault(CfgRegisterUsername, "")
	v.SetDefault(CfgRegisterPassword, "")
	v.SetDefault(CfgRegisterClientID, "")
	v.SetDefault(CfgRegisterEnduserClientID, "")
	v.SetDefault(CfgRecaptchaURL, "https://www.google.com/recaptcha/api/siteverify")
	v.SetDefault(CfgRecaptchaSecret, "")
	v.SetDefault(CfgSsePublicURL, "")

	// First level of override.
	pflag.String(CfgConfigFile, v.GetString(CfgConfigFile), "The configuration file path can be relative or absolute.")
	v.BindPFlag(CfgConfigFile, pflag.Lookup(CfgConfigFile))
	pflag.Parse()

	// Bind ENV variables
	// We use env variables to bind Openshift secrets
	var censoredParameters = map[string]bool{}

	v.BindEnv(CfgRegisterUsername, "CT_BRIDGE_REGISTER_USERNAME")
	v.BindEnv(CfgRegisterPassword, "CT_BRIDGE_REGISTER_PASSWORD")
	v.BindEnv(CfgRecaptchaSecret, "CT_BRIDGE_RECAPTCHA_SECRET")
	censoredParameters[CfgRecaptchaSecret] = true
	censoredParameters[CfgRegisterPassword] = true

	v.BindEnv("influx-username", "CT_BRIDGE_INFLUX_USERNAME")
	v.BindEnv("influx-password", "CT_BRIDGE_INFLUX_PASSWORD")
	censoredParameters["influx-password"] = true

	v.BindEnv(CfgSentryDsn, "CT_BRIDGE_SENTRY_DSN")
	censoredParameters[CfgSentryDsn] = true

	v.BindEnv(CfgEventBasicAuthToken, "CT_BRIDGE_EVENT_BASIC_AUTH")
	censoredParameters[CfgEventBasicAuthToken] = true

	v.BindEnv(CfgValidationBasicAuthToken, "CT_BRIDGE_VALIDATION_BASIC_AUTH")
	censoredParameters[CfgValidationBasicAuthToken] = true

	// Load and log config.
	v.SetConfigFile(v.GetString(CfgConfigFile))
	var err = v.ReadInConfig()
	if err != nil {
		logger.Error(ctx, "error", err)
	}

	// If the host/port is not set, we consider the components deactivated.
	v.Set("influx", v.GetString("influx-host-port") != "")
	v.Set("sentry", v.GetString(CfgSentryDsn) != "")
	v.Set("jaeger", v.GetString("jaeger-sampler-host-port") != "")

	// Log config in alphabetical order.
	var keys = v.AllKeys()
	sort.Strings(keys)

	for _, k := range keys {
		if _, censored := censoredParameters[k]; censored {
			logger.Info(ctx, k, "*************")
		} else if strings.Contains(k, "password") {
			logger.Info(ctx, k, "*************")
		} else {
			logger.Info(ctx, k, v.Get(k))
		}
	}
	return v
}

func configureEventsHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = events.MakeEventsHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureStatisiticsHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = statistics.MakeStatisticsHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureValidationHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, expectedToken string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = validation.MakeValidationHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPBasicAuthenticationMW(expectedToken, logger)(handler)
		return handler
	}
}

func configureManagementHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = management.MakeManagementHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureRightsHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, authorizationManager security.AuthorizationManager, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) http.Handler {
	var handler http.Handler
	handler = commonhttp.MakeRightsHandler(authorizationManager)
	handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
	handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
	return handler
}

func configureAccountHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = account.MakeAccountHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureKYCHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client,
	audienceRequired string, tracer tracing.OpentracingClient, idRetriever middleware.IDRetriever, configReader middleware.AdminConfigurationRetriever,
	verifyAvailableChecks bool, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = kyc.MakeKYCHandler(endpoint, logger)
		if verifyAvailableChecks {
			handler = middleware.MakeEndpointAvailableCheckMW(configuration.CheckKeyPhysical, idRetriever, configReader, logger)(handler)
		}
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureRegisterHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, recaptchaURL, recaptchaSecret string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = register.MakeRegisterHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = register.MakeHTTPRecaptchaValidationMW(recaptchaURL, recaptchaSecret, logger)(handler)
		return handler
	}
}

func configurePublicRegisterHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = register.MakeRegisterHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		return handler
	}
}

func createConfigurationDBModule(configDBConn sqltypes.CloudtrustDB, influxMetrics metrics.Metrics, logger log.Logger) keycloakb.ConfigurationDBModule {
	var configDBModule keycloakb.ConfigurationDBModule
	{
		configDBModule = keycloakb.NewConfigurationDBModule(configDBConn, logger)
		configDBModule = keycloakb.MakeConfigurationDBModuleInstrumentingMW(influxMetrics.NewHistogram("configDB_module"))(configDBModule)
	}
	return configDBModule
}

func configureEventsDbModule(baseEventsDBModule database.EventsDBModule, influxMetrics metrics.Metrics, logger log.Logger, tracer tracing.OpentracingClient) database.EventsDBModule {
	eventsDBModule := event.MakeEventsDBModuleInstrumentingMW(influxMetrics.NewHistogram("eventsDB_module"))(baseEventsDBModule)
	eventsDBModule = event.MakeEventsDBModuleLoggingMW(log.With(logger, "mw", "module", "unit", "eventsDB"))(eventsDBModule)
	eventsDBModule = event.MakeEventsDBModuleTracingMW(tracer)(eventsDBModule)
	return eventsDBModule
}

func prepareEndpoint(e cs.Endpoint, endpointName string, influxMetrics metrics.Metrics, logger log.Logger, tracer tracing.OpentracingClient, rateLimit int) endpoint.Endpoint {
	e = middleware.MakeEndpointInstrumentingMW(influxMetrics, endpointName)(e)
	e = middleware.MakeEndpointLoggingMW(log.With(logger, "mw", endpointName))(e)
	e = tracer.MakeEndpointTracingMW(endpointName)(e)
	return keycloakb.LimitRate(e, rateLimit)
}

func prepareEndpointWithoutLogging(e cs.Endpoint, endpointName string, influxMetrics metrics.Metrics, tracer tracing.OpentracingClient, rateLimit int) endpoint.Endpoint {
	e = middleware.MakeEndpointInstrumentingMW(influxMetrics, endpointName)(e)
	e = tracer.MakeEndpointTracingMW(endpointName)(e)
	return keycloakb.LimitRate(e, rateLimit)
}
