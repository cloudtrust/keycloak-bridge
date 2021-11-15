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

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/database/sqltypes"
	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/healthcheck"
	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/idgenerator"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/metrics"
	"github.com/cloudtrust/common-service/middleware"
	"github.com/cloudtrust/common-service/security"
	"github.com/cloudtrust/common-service/tracing"
	"github.com/cloudtrust/common-service/tracking"
	"github.com/cloudtrust/keycloak-bridge/internal/business"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications"
	"github.com/cloudtrust/keycloak-bridge/pkg/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/export"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc"
	"github.com/cloudtrust/keycloak-bridge/pkg/management"
	mobile "github.com/cloudtrust/keycloak-bridge/pkg/mobile"
	"github.com/cloudtrust/keycloak-bridge/pkg/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/tasks"
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
	"golang.org/x/time/rate"
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
	pathHealthCheck     = "/health/check"

	RateKeyAccount          = iota
	RateKeyCommunications   = iota
	RateKeyEvents           = iota
	RateKeyKYC              = iota
	RateKeyManagement       = iota
	RateKeyManagementStatus = iota
	RateKeyMobile           = iota
	RateKeyMonitoring       = iota
	RateKeyRegister         = iota
	RateKeyStatistics       = iota
	RateKeyTasks            = iota
	RateKeyValidation       = iota

	cfgConfigFile               = "config-file"
	cfgHTTPAddrInternal         = "internal-http-host-port"
	cfgHTTPAddrManagement       = "management-http-host-port"
	cfgHTTPAddrAccount          = "account-http-host-port"
	cfgHTTPAddrRegister         = "register-http-host-port"
	cfgHTTPAddrMobile           = "mobile-http-host-port"
	cfgHTTPAddrMonitoring       = "monitoring-http-host-port"
	cfgAddrTokenProviderMap     = "keycloak-oidc-uri-map"
	cfgAddrAPI                  = "keycloak-api-uri"
	cfgTimeout                  = "keycloak-timeout"
	cfgAudienceRequired         = "audience-required"
	cfgMobileAudienceRequired   = "mobile-audience-required"
	cfgValidationBasicAuthToken = "validation-basic-auth-token"
	cfgPprofRouteEnabled        = "pprof-route-enabled"
	cfgInfluxWriteInterval      = "influx-write-interval"
	cfgSentryDsn                = "sentry-dsn"
	cfgAuditRwDbParams          = "db-audit-rw"
	cfgAuditRoDbParams          = "db-audit-ro"
	cfgConfigRwDbParams         = "db-config-rw"
	cfgConfigRoDbParams         = "db-config-ro"
	cfgUsersRwDbParams          = "db-users-rw"
	cfgRateKeyValidation        = "rate-validation"
	cfgRateKeyCommunications    = "rate-communications"
	cfgRateKeyAccount           = "rate-account"
	cfgRateKeyMobile            = "rate-mobile"
	cfgRateKeyMonitoring        = "rate-monitoring"
	cfgRateKeyManagement        = "rate-management"
	cfgRateKeyManagementStatus  = "rate-management-status"
	cfgRateKeyStatistics        = "rate-statistics"
	cfgRateKeyEvents            = "rate-events"
	cfgRateKeyRegister          = "rate-register"
	cfgRateKeyTasks             = "rate-tasks"
	cfgRateKeyKYC               = "rate-kyc"
	cfgAllowedOrigins           = "cors-allowed-origins"
	cfgAllowedMethods           = "cors-allowed-methods"
	cfgAllowCredentials         = "cors-allow-credentials"
	cfgAllowedHeaders           = "cors-allowed-headers"
	cfgExposedHeaders           = "cors-exposed-headers"
	cfgDebug                    = "cors-debug"
	cfgLogLevel                 = "log-level"
	cfgAccessLogsEnabled        = "access-logs"
	cfgTrustIDGroups            = "trustid-groups"
	cfgRegisterRealm            = "register-realm"
	cfgTechnicalRealm           = "technical-realm"
	cfgTechnicalUsername        = "technical-username"
	cfgTechnicalPassword        = "technical-password"
	cfgTechnicalClientID        = "technical-client-id"
	cfgRecaptchaURL             = "recaptcha-url"
	cfgRecaptchaSecret          = "recaptcha-secret"
	cfgDbAesGcmKey              = "db-aesgcm-key"
	cfgDbAesGcmTagSize          = "db-aesgcm-tag-size"
	cfgArchiveRwDbParams        = "db-archive-rw"
	cfgDbArchiveAesGcmKey       = "db-archive-aesgcm-key"
	cfgDbArchiveAesGcmTagSize   = "db-archive-aesgcm-tag-size"
	cfgMaxLifeSpan              = "max-lifespan"
	cfgGlnRefDataEnabled        = "gln-refdata-enabled"
	cfgGlnRefDataURI            = "gln-refdata-uri"
	cfgGlnRefDataTimeout        = "gln-refdata-timeout"
	cfgGlnNaRegEnabled          = "gln-nareg-enabled"
	cfgGlnNaRegURI              = "gln-nareg-uri"
	cfgGlnNaRegTimeout          = "gln-nareg-timeout"
	cfgGlnPsyRegEnabled         = "gln-psyreg-enabled"
	cfgGlnPsyRegURI             = "gln-psyreg-uri"
	cfgGlnPsyRegTimeout         = "gln-psyreg-timeout"
	cfgGlnMedRegEnabled         = "gln-medreg-enabled"
	cfgGlnMedRegURI             = "gln-medreg-uri"
	cfgGlnMedRegTimeout         = "gln-medreg-timeout"

	tokenProviderDefaultKey = "default"
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
		httpAddrInternal   = c.GetString(cfgHTTPAddrInternal)
		httpAddrManagement = c.GetString(cfgHTTPAddrManagement)
		httpAddrAccount    = c.GetString(cfgHTTPAddrAccount)
		httpAddrRegister   = c.GetString(cfgHTTPAddrRegister)
		httpAddrMobile     = c.GetString(cfgHTTPAddrMobile)
		httpAddrMonitoring = c.GetString(cfgHTTPAddrMonitoring)

		// Enabled units
		pprofRouteEnabled = c.GetBool(cfgPprofRouteEnabled)

		// Influx
		influxWriteInterval = c.GetDuration(cfgInfluxWriteInterval)

		// DB - for the moment used just for audit events
		auditRwDbParams = database.GetDbConfig(c, cfgAuditRwDbParams)

		// DB - Read only user for audit events
		auditRoDbParams = database.GetDbConfig(c, cfgAuditRoDbParams)

		// DB for custom configuration
		configRwDbParams = database.GetDbConfig(c, cfgConfigRwDbParams)
		configRoDbParams = database.GetDbConfig(c, cfgConfigRoDbParams)

		// DB for users
		usersRwDbParams = database.GetDbConfig(c, cfgUsersRwDbParams)

		// DB for archiving users
		archiveRwDbParams = database.GetDbConfig(c, cfgArchiveRwDbParams)

		// Rate limiting
		rateLimit = map[RateKey]int{
			RateKeyValidation:       c.GetInt(cfgRateKeyValidation),
			RateKeyCommunications:   c.GetInt(cfgRateKeyCommunications),
			RateKeyAccount:          c.GetInt(cfgRateKeyAccount),
			RateKeyMobile:           c.GetInt(cfgRateKeyMobile),
			RateKeyMonitoring:       c.GetInt(cfgRateKeyMonitoring),
			RateKeyManagement:       c.GetInt(cfgRateKeyManagement),
			RateKeyManagementStatus: c.GetInt(cfgRateKeyManagementStatus),
			RateKeyStatistics:       c.GetInt(cfgRateKeyStatistics),
			RateKeyEvents:           c.GetInt(cfgRateKeyEvents),
			RateKeyRegister:         c.GetInt(cfgRateKeyRegister),
			RateKeyTasks:            c.GetInt(cfgRateKeyTasks),
			RateKeyKYC:              c.GetInt(cfgRateKeyKYC),
		}

		corsOptions = cors.Options{
			AllowedOrigins:   c.GetStringSlice(cfgAllowedOrigins),
			AllowedMethods:   c.GetStringSlice(cfgAllowedMethods),
			AllowCredentials: c.GetBool(cfgAllowCredentials),
			AllowedHeaders:   c.GetStringSlice(cfgAllowedHeaders),
			ExposedHeaders:   c.GetStringSlice(cfgExposedHeaders),
			Debug:            c.GetBool(cfgDebug),
		}

		logLevel = c.GetString(cfgLogLevel)

		// Access logs
		accessLogsEnabled = c.GetBool(cfgAccessLogsEnabled)

		// Register parameters
		registerRealm   = c.GetString(cfgRegisterRealm)
		recaptchaURL    = c.GetString(cfgRecaptchaURL)
		recaptchaSecret = c.GetString(cfgRecaptchaSecret)

		// Technical parameters
		technicalRealm    = c.GetString(cfgTechnicalRealm)
		technicalUsername = c.GetString(cfgTechnicalUsername)
		technicalPassword = c.GetString(cfgTechnicalPassword)
		technicalClientID = c.GetString(cfgTechnicalClientID)

		// Max lifespan (maximum active duration of sent links by email)
		maxLifeSpan = int(c.GetDuration(cfgMaxLifeSpan) / time.Second)

		// GLN
		glnRefDataEnabled = c.GetBool(cfgGlnRefDataEnabled)
		glnRefDataURI     = c.GetString(cfgGlnRefDataURI)
		glnRefDataTimeout = c.GetDuration(cfgGlnRefDataTimeout)
		glnNaRegEnabled   = c.GetBool(cfgGlnNaRegEnabled)
		glnNaRegURI       = c.GetString(cfgGlnNaRegURI)
		glnNaRegTimeout   = c.GetDuration(cfgGlnNaRegTimeout)
		glnMedRegEnabled  = c.GetBool(cfgGlnMedRegEnabled)
		glnMedRegURI      = c.GetString(cfgGlnMedRegURI)
		glnMedRegTimeout  = c.GetDuration(cfgGlnMedRegTimeout)
		glnPsyRegEnabled  = c.GetBool(cfgGlnPsyRegEnabled)
		glnPsyRegURI      = c.GetString(cfgGlnPsyRegURI)
		glnPsyRegTimeout  = c.GetDuration(cfgGlnPsyRegTimeout)
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
			logger.Error(ctx, "err", err)
			return
		}

		logger = log.AllowLevel(logger, level)
	}

	// Security - Audience required
	var audienceRequired string
	{
		audienceRequired = c.GetString(cfgAudienceRequired)

		if audienceRequired == "" {
			logger.Error(ctx, "msg", "audience parameter(audience-required) cannot be empty")
			return
		}
	}

	// Security - Mobile audience required
	var mobileAudienceRequired string
	{
		mobileAudienceRequired = c.GetString(cfgMobileAudienceRequired)

		if mobileAudienceRequired == "" {
			logger.Error(ctx, "msg", "mobile audience parameter(mobile-audience-required) cannot be empty")
			return
		}
	}

	var validationExpectedAuthToken string
	{
		validationExpectedAuthToken = c.GetString(cfgValidationBasicAuthToken)

		if validationExpectedAuthToken == "" {
			logger.Error(ctx, "msg", "password for validation endpoint (validation-basic-auth-token) cannot be empty")
			return
		}
	}

	errorhandler.SetEmitter(keycloakb.ComponentName)

	// Security - AES encryption mechanism for users PII
	aesEncryption, err := security.NewAesGcmEncrypterFromBase64(c.GetString(cfgDbAesGcmKey), c.GetInt(cfgDbAesGcmTagSize))
	if err != nil {
		logger.Error(ctx, "msg", "could not create AES-GCM encrypting tool instance (users)", "err", err)
		return
	}
	archiveAesEncryption, err := security.NewAesGcmEncrypterFromBase64(c.GetString(cfgDbArchiveAesGcmKey), c.GetInt(cfgDbArchiveAesGcmTagSize))
	if err != nil {
		logger.Error(ctx, "msg", "could not create AES-GCM encrypting tool instance (archive)", "err", err)
		return
	}

	// Security - allowed trustID groups
	var trustIDGroups = c.GetStringSlice(cfgTrustIDGroups)

	// Keycloak
	var tokenProviderMap = c.GetStringMapString(cfgAddrTokenProviderMap)
	var uriProvider keycloak.KeycloakURIProvider
	{
		uriProvider, err = toolbox.NewKeycloakURIProvider(tokenProviderMap, tokenProviderDefaultKey)
		if err != nil {
			logger.Error(ctx, "msg", "can't create Keycloak URI provider", "err", err)
			return
		}
	}
	var keycloakConfig = keycloak.Config{
		AddrTokenProvider: uriProvider.GetAllBaseURIs(),
		URIProvider:       uriProvider,
		AddrAPI:           c.GetString(cfgAddrAPI),
		Timeout:           c.GetDuration(cfgTimeout),
	}

	// Keycloak client.
	var keycloakClient *keycloakapi.Client
	{
		var err error
		keycloakClient, err = keycloakapi.New(keycloakConfig)

		if err != nil {
			logger.Error(ctx, "msg", "could not create Keycloak client", "err", err)
			return
		}
	}

	// Recaptcha secret
	if recaptchaSecret == "" {
		logger.Error(ctx, "msg", "Recaptcha secret is not configured")
		return
	}

	// Keycloak adaptor for common-service library
	commonKcAdaptor := keycloakb.NewKeycloakAuthClient(keycloakClient, logger)

	var sentryClient tracking.SentryTracking
	{
		var logger = log.With(logger, "unit", "sentry")
		var err error
		sentryClient, err = tracking.NewSentry(c, "sentry")
		if err != nil {
			logger.Error(ctx, "msg", "could not create Sentry client", "err", err)
			return
		}
		defer sentryClient.Close()
	}

	var influxMetrics metrics.Metrics
	{
		var err error
		influxMetrics, err = metrics.NewMetrics(c, "influx", logger)
		if err != nil {
			logger.Error(ctx, "msg", "could not create Influx client", "err", err)
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
			logger.Error(ctx, "msg", "could not create Jaeger tracer", "err", err)
			return
		}
		defer tracer.Close()
	}

	var eventsDBConn sqltypes.CloudtrustDB
	{
		var err error
		eventsDBConn, err = database.NewReconnectableCloudtrustDB(auditRwDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create R/W DB connection for audit events", "err", err)
			return
		}
	}

	var eventsRODBConn sqltypes.CloudtrustDB
	{
		var err error
		eventsRODBConn, err = database.NewReconnectableCloudtrustDB(auditRoDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create RO DB connection for audit events", "err", err)
			return
		}
	}

	var configurationRwDBConn sqltypes.CloudtrustDB
	{
		var err error
		configurationRwDBConn, err = database.NewReconnectableCloudtrustDB(configRwDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for configuration storage (RW)", "err", err)
			return
		}
	}

	var configurationRoDBConn sqltypes.CloudtrustDB
	{
		var err error
		configurationRoDBConn, err = database.NewReconnectableCloudtrustDB(configRoDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for configuration storage (RO)", "err", err)
			return
		}
	}

	var usersRwDBConn sqltypes.CloudtrustDB
	{
		var err error
		usersRwDBConn, err = database.NewReconnectableCloudtrustDB(usersRwDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for users (RW)", "err", err)
			return
		}
	}

	var archiveRwDBConn sqltypes.CloudtrustDB
	{
		var err error
		archiveRwDBConn, err = database.NewReconnectableCloudtrustDB(archiveRwDbParams)
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for archive (RW)", "err", err)
			return
		}
	}

	// Create technical OIDC token provider and validate technical user credentials
	var technicalTokenProvider toolbox.OidcTokenProvider
	{
		technicalTokenProvider = toolbox.NewOidcTokenProvider(keycloakConfig, technicalRealm, technicalUsername, technicalPassword, technicalClientID, logger)
		for realm := range tokenProviderMap {
			var _, err = technicalTokenProvider.ProvideTokenForRealm(context.Background(), realm)
			if err != nil {
				logger.Warn(context.Background(), "msg", "OIDC token provider validation failed for technical user", "err", err.Error(), "realm", realm)
			}
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
	healthChecker.AddDatabase("Archive RO", archiveRwDBConn, healthCheckCacheDuration)
	healthChecker.AddHTTPEndpoint("Keycloak", keycloakConfig.AddrAPI, httpTimeout, 200, healthCheckCacheDuration)

	// Actions allowed in Authorization Manager
	var authActions = security.AppendActionNames(nil, events.GetActions(), kyc.GetActions(), management.GetActions(), statistics.GetActions(), tasks.GetActions())
	authActions = mobile.AppendIDNowActions(authActions)

	// Authorization Manager
	var authorizationManager security.AuthorizationManager
	{
		var authorizationLogger = log.With(logger, "svc", "authorization")

		var configurationReaderDBModule *configuration.ConfigurationReaderDBModule
		{
			configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, authorizationLogger, authActions)
		}

		var err error
		authorizationManager, err = security.NewAuthorizationManager(configurationReaderDBModule, commonKcAdaptor, authorizationLogger)

		if err != nil {
			logger.Error(ctx, "msg", "could not load authorizations", "err", err)
			return
		}
	}

	// GLN verifier
	var glnLookupProviders []business.GlnLookupProvider
	{
		if glnRefDataEnabled {
			glnRefDataLookup, err := business.NewRefDataLookup(glnRefDataURI, glnRefDataTimeout, logger)
			if err != nil {
				logger.Error(ctx, "msg", "can't initialize GLN RefData lookup", "err", err.Error())
				return
			}
			glnLookupProviders = append(glnLookupProviders, glnRefDataLookup)
		}
		if glnMedRegEnabled {
			glnMedRegLookup, err := business.NewMedRegOmLookup(glnMedRegURI, glnMedRegTimeout, logger)
			if err != nil {
				logger.Error(ctx, "msg", "can't initialize GLN MedReg lookup", "err", err.Error())
				return
			}
			glnLookupProviders = append(glnLookupProviders, glnMedRegLookup)
		}
		if glnNaRegEnabled {
			glnNaRegLookup, err := business.NewNaRegLookup(glnNaRegURI, glnNaRegTimeout, logger)
			if err != nil {
				logger.Error(ctx, "msg", "can't initialize GLN NaReg lookup", "err", err.Error())
				return
			}
			glnLookupProviders = append(glnLookupProviders, glnNaRegLookup)
		}
		if glnPsyRegEnabled {
			glnPsyRegLookup, err := business.NewPsyRegLookup(glnPsyRegURI, glnPsyRegTimeout, logger)
			if err != nil {
				logger.Error(ctx, "msg", "can't initialize GLN PsyReg lookup", "err", err.Error())
				return
			}
			glnLookupProviders = append(glnLookupProviders, glnPsyRegLookup)
		}
	}
	var glnVerifier = business.NewGlnVerifier(glnLookupProviders...)

	// Validation service.
	var validationEndpoints validation.Endpoints
	{
		var validationLogger = log.With(logger, "svc", "validation")

		// module to store validation events API calls
		eventsDBModule := database.NewEventsDBModule(eventsDBConn)

		// module for storing and retrieving details of the users
		var usersDBModule = keycloakb.NewUsersDetailsDBModule(usersRwDBConn, aesEncryption, validationLogger)

		// module for archiving users
		var archiveDBModule = keycloakb.NewArchiveDBModule(archiveRwDBConn, archiveAesEncryption, validationLogger)

		var configurationReaderDBModule *configuration.ConfigurationReaderDBModule
		{
			configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, validationLogger, authActions)
		}

		// accreditations module
		var accredsModule keycloakb.AccreditationsModule
		{
			var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, validationLogger)
			accredsModule = keycloakb.NewAccreditationsModule(keycloakClient, configurationReaderDBModule, validationLogger)
		}

		validationComponent := validation.NewComponent(keycloakClient, technicalTokenProvider, usersDBModule, archiveDBModule, eventsDBModule, accredsModule, configurationReaderDBModule, validationLogger)

		var rateLimitValidation = rateLimit[RateKeyValidation]
		validationEndpoints = validation.Endpoints{
			GetUser:            prepareEndpoint(validation.MakeGetUserEndpoint(validationComponent), "get_user", influxMetrics, validationLogger, tracer, rateLimitValidation),
			UpdateUser:         prepareEndpoint(validation.MakeUpdateUserEndpoint(validationComponent), "update_user", influxMetrics, validationLogger, tracer, rateLimitValidation),
			CreateCheck:        prepareEndpoint(validation.MakeCreateCheckEndpoint(validationComponent), "create_check", influxMetrics, validationLogger, tracer, rateLimitValidation),
			CreatePendingCheck: prepareEndpoint(validation.MakeCreatePendingCheckEndpoint(validationComponent), "create_check_pending", influxMetrics, validationLogger, tracer, rateLimitValidation),
			DeletePendingCheck: prepareEndpoint(validation.MakeDeletePendingCheckEndpoint(validationComponent), "delete_check_pending", influxMetrics, validationLogger, tracer, rateLimitValidation),
		}
	}

	// Communications service.
	var communicationsEndpoints communications.Endpoints
	{
		var communicationsLogger = log.With(logger, "svc", "communications")

		communicationsComponent := communications.NewComponent(keycloakClient, communicationsLogger)
		// MakeAuthorizationCommunicationsComponentMW not called !!??

		var rateLimitCommunications = rateLimit[RateKeyCommunications]
		communicationsEndpoints = communications.Endpoints{
			SendEmail: prepareEndpoint(communications.MakeSendEmailEndpoint(communicationsComponent), "send_email", influxMetrics, communicationsLogger, tracer, rateLimitCommunications),
			SendSMS:   prepareEndpoint(communications.MakeSendSMSEndpoint(communicationsComponent), "send_sms", influxMetrics, communicationsLogger, tracer, rateLimitCommunications),
		}
	}

	// Tasks service.
	var tasksEndpoints tasks.Endpoints
	{
		var tasksLogger = log.With(logger, "svc", "tasks")

		// module for storing and retrieving details of the users
		var usersDBModule = keycloakb.NewUsersDetailsDBModule(usersRwDBConn, aesEncryption, tasksLogger)

		// module to store validation events API calls
		eventsDBModule := database.NewEventsDBModule(eventsDBConn)

		tasksComponent := tasks.NewComponent(keycloakClient, usersDBModule, eventsDBModule, tasksLogger)
		tasksComponent = tasks.MakeAuthorizationManagementComponentMW(log.With(tasksLogger, "mw", "endpoint"), authorizationManager)(tasksComponent)

		var rateLimitTasks = rateLimit[RateKeyTasks]
		tasksEndpoints = tasks.Endpoints{
			DeleteDeniedToUUsers: prepareEndpoint(tasks.MakeDeleteDeniedTermsOfUseUsersEndpoint(tasksComponent), "del_denied_tou_users", influxMetrics, tasksLogger, tracer, rateLimitTasks),
		}
	}

	// Statistics service.
	var statisticsEndpoints statistics.Endpoints
	{
		var statisticsLogger = log.With(logger, "svc", "statistics")

		//module for reading events from the DB
		eventsRODBModule := keycloakb.NewEventsDBModule(eventsRODBConn)

		statisticsComponent := statistics.NewComponent(eventsRODBModule, keycloakClient, statisticsLogger)
		statisticsComponent = statistics.MakeAuthorizationManagementComponentMW(log.With(statisticsLogger, "mw", "endpoint"), authorizationManager)(statisticsComponent)

		var rateLimitStatistics = rateLimit[RateKeyStatistics]
		statisticsEndpoints = statistics.Endpoints{
			GetActions:                      prepareEndpoint(statistics.MakeGetActionsEndpoint(statisticsComponent), "get_actions", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetStatistics:                   prepareEndpoint(statistics.MakeGetStatisticsEndpoint(statisticsComponent), "get_statistics", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
			GetStatisticsIdentifications:    prepareEndpoint(statistics.MakeGetStatisticsIdentificationsEndpoint(statisticsComponent), "get_statistics_identifications", influxMetrics, statisticsLogger, tracer, rateLimitStatistics),
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
		eventsRWDBModule := database.NewEventsDBModule(eventsDBConn)

		//module for reading events from the DB
		eventsRODBModule := keycloakb.NewEventsDBModule(eventsRODBConn)

		eventsComponent := events.NewComponent(eventsRODBModule, eventsRWDBModule, eventsLogger)
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
		eventsDBModule := database.NewEventsDBModule(eventsDBConn)

		// module for storing and retrieving the custom configuration
		var configDBModule = createConfigurationDBModule(configurationRwDBConn, influxMetrics, managementLogger)

		// module for storing and retrieving details of the users
		var usersDBModule = keycloakb.NewUsersDetailsDBModule(usersRwDBConn, aesEncryption, managementLogger)

		// module for onboarding process
		var onboardingModule = keycloakb.NewOnboardingModule(keycloakClient, keycloakConfig.URIProvider, logger)

		var keycloakComponent management.Component
		{
			keycloakComponent = management.NewComponent(keycloakClient, usersDBModule, eventsDBModule, configDBModule, onboardingModule, trustIDGroups, registerRealm, glnVerifier, managementLogger)
			keycloakComponent = management.MakeAuthorizationManagementComponentMW(log.With(managementLogger, "mw", "endpoint"), authorizationManager)(keycloakComponent)
		}

		var rateLimitMgmt = rateLimit[RateKeyManagement]
		var rateLimitMgmtStatus = rateLimit[RateKeyManagementStatus]
		managementEndpoints = management.Endpoints{
			GetActions: prepareEndpoint(management.MakeGetActionsEndpoint(keycloakComponent), "get_actions_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetRealms: prepareEndpoint(management.MakeGetRealmsEndpoint(keycloakComponent), "realms_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRealm:  prepareEndpoint(management.MakeGetRealmEndpoint(keycloakComponent), "realm_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetClients:         prepareEndpoint(management.MakeGetClientsEndpoint(keycloakComponent), "get_clients_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetClient:          prepareEndpoint(management.MakeGetClientEndpoint(keycloakComponent), "get_client_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRequiredActions: prepareEndpoint(management.MakeGetRequiredActionsEndpoint(keycloakComponent), "get_required-actions_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			CreateUser:                  prepareEndpoint(management.MakeCreateUserEndpoint(keycloakComponent, managementLogger), "create_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUser:                     prepareEndpoint(management.MakeGetUserEndpoint(keycloakComponent), "get_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UpdateUser:                  prepareEndpoint(management.MakeUpdateUserEndpoint(keycloakComponent), "update_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			LockUser:                    prepareEndpoint(management.MakeLockUserEndpoint(keycloakComponent), "lock_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UnlockUser:                  prepareEndpoint(management.MakeUnlockUserEndpoint(keycloakComponent), "unlock_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteUser:                  prepareEndpoint(management.MakeDeleteUserEndpoint(keycloakComponent), "delete_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUsers:                    prepareEndpoint(management.MakeGetUsersEndpoint(keycloakComponent), "get_users_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUserChecks:               prepareEndpoint(management.MakeGetUserChecksEndpoint(keycloakComponent), "get_user_checks", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetUserAccountStatus:        prepareEndpoint(management.MakeGetUserAccountStatusEndpoint(keycloakComponent), "get_user_accountstatus", influxMetrics, managementLogger, tracer, rateLimitMgmtStatus),
			GetUserAccountStatusByEmail: prepareEndpoint(management.MakeGetUserAccountStatusByEmailEndpoint(keycloakComponent), "get_user_accountstatus_by_email", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetGroupsOfUser:             prepareEndpoint(management.MakeGetGroupsOfUserEndpoint(keycloakComponent), "get_user_groups", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			AddGroupToUser:              prepareEndpoint(management.MakeAddGroupToUserEndpoint(keycloakComponent), "add_user_group", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteGroupForUser:          prepareEndpoint(management.MakeDeleteGroupForUserEndpoint(keycloakComponent), "del_user_group", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetAvailableTrustIDGroups:   prepareEndpoint(management.MakeGetAvailableTrustIDGroupsEndpoint(keycloakComponent), "get_available_trustid_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetTrustIDGroupsOfUser:      prepareEndpoint(management.MakeGetTrustIDGroupsOfUserEndpoint(keycloakComponent), "get_user_trustid_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			SetTrustIDGroupsToUser:      prepareEndpoint(management.MakeSetTrustIDGroupsToUserEndpoint(keycloakComponent), "set_user_trustid_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRolesOfUser:              prepareEndpoint(management.MakeGetRolesOfUserEndpoint(keycloakComponent), "get_user_roles", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			AddRoleToUser:               prepareEndpoint(management.MakeAddRoleToUserEndpoint(keycloakComponent), "add_user_role", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteRoleForUser:           prepareEndpoint(management.MakeDeleteRoleForUserEndpoint(keycloakComponent), "delete_user_role", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetRoles: prepareEndpoint(management.MakeGetRolesEndpoint(keycloakComponent), "get_roles_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetRole:  prepareEndpoint(management.MakeGetRoleEndpoint(keycloakComponent), "get_role_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetGroups:            prepareEndpoint(management.MakeGetGroupsEndpoint(keycloakComponent), "get_groups_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			CreateGroup:          prepareEndpoint(management.MakeCreateGroupEndpoint(keycloakComponent, managementLogger), "create_group_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteGroup:          prepareEndpoint(management.MakeDeleteGroupEndpoint(keycloakComponent), "delete_group_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetAuthorizations:    prepareEndpoint(management.MakeGetAuthorizationsEndpoint(keycloakComponent), "get_authorizations_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			UpdateAuthorizations: prepareEndpoint(management.MakeUpdateAuthorizationsEndpoint(keycloakComponent), "update_authorizations_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			GetClientRoles:       prepareEndpoint(management.MakeGetClientRolesEndpoint(keycloakComponent), "get_client_roles_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			CreateClientRole:     prepareEndpoint(management.MakeCreateClientRoleEndpoint(keycloakComponent, managementLogger), "create_client_role_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetClientRoleForUser: prepareEndpoint(management.MakeGetClientRolesForUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			AddClientRoleToUser:  prepareEndpoint(management.MakeAddClientRolesToUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

			ResetPassword:                  prepareEndpointWithoutLogging(management.MakeResetPasswordEndpoint(keycloakComponent), "reset_password_endpoint", influxMetrics, tracer, rateLimitMgmt),
			ExecuteActionsEmail:            prepareEndpoint(management.MakeExecuteActionsEmailEndpoint(keycloakComponent), "execute_actions_email_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			SendOnboardingEmail:            prepareEndpoint(management.MakeSendOnboardingEmailEndpoint(keycloakComponent, maxLifeSpan), "send_onboarding_email_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			SendReminderEmail:              prepareEndpoint(management.MakeSendReminderEmailEndpoint(keycloakComponent), "send_reminder_email_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			SendSmsCode:                    prepareEndpoint(management.MakeSendSmsCodeEndpoint(keycloakComponent), "send_sms_code_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			ResetSmsCounter:                prepareEndpoint(management.MakeResetSmsCounterEndpoint(keycloakComponent), "reset_sms_counter_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			CreateRecoveryCode:             prepareEndpoint(management.MakeCreateRecoveryCodeEndpoint(keycloakComponent), "create_recovery_code_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			CreateActivationCode:           prepareEndpoint(management.MakeCreateActivationCodeEndpoint(keycloakComponent), "create_activation_code_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetCredentialsForUser:          prepareEndpoint(management.MakeGetCredentialsForUserEndpoint(keycloakComponent), "get_credentials_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			DeleteCredentialsForUser:       prepareEndpoint(management.MakeDeleteCredentialsForUserEndpoint(keycloakComponent), "delete_credentials_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			ResetCredentialFailuresForUser: prepareEndpoint(management.MakeResetCredentialFailuresForUserEndpoint(keycloakComponent), "reset_credential_failures_for_user_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			ClearUserLoginFailures:         prepareEndpoint(management.MakeClearUserLoginFailures(keycloakComponent), "clear_user_login_failures_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),
			GetAttackDetectionStatus:       prepareEndpoint(management.MakeGetAttackDetectionStatus(keycloakComponent), "get_attack_detection_status_endpoint", influxMetrics, managementLogger, tracer, rateLimitMgmt),

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
		eventsDBModule := database.NewEventsDBModule(eventsDBConn)

		// module for retrieving the custom configuration
		var configDBModule keycloakb.ConfigurationDBModule
		{
			configDBModule = keycloakb.NewConfigurationDBModule(configurationRoDBConn, accountLogger)
			configDBModule = keycloakb.MakeConfigurationDBModuleInstrumentingMW(influxMetrics.NewHistogram("configDB_module"))(configDBModule)
		}

		var kcTechClient keycloakb.KeycloakTechnicalClient
		{
			kcTechClient = keycloakb.NewKeycloakTechnicalClient(technicalTokenProvider, keycloakClient, accountLogger)
		}

		// module for storing and retrieving details of the self-registered users
		var usersDBModule = keycloakb.NewUsersDetailsDBModule(usersRwDBConn, aesEncryption, accountLogger)

		// new module for account service
		accountComponent := account.NewComponent(keycloakClient.AccountClient(), kcTechClient, eventsDBModule, configDBModule, usersDBModule, glnVerifier, accountLogger)
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

	// Mobile service.
	var mobileEndpoints mobile.Endpoints
	{
		var mobileLogger = log.With(logger, "svc", "mobile")

		// module for retrieving the custom configuration
		var configDBModule keycloakb.ConfigurationDBModule
		{
			configDBModule = keycloakb.NewConfigurationDBModule(configurationRoDBConn, mobileLogger)
			configDBModule = keycloakb.MakeConfigurationDBModuleInstrumentingMW(influxMetrics.NewHistogram("configDB_module"))(configDBModule)
		}

		// module for storing and retrieving details of the self-registered users
		var usersDBModule = keycloakb.NewUsersDetailsDBModule(usersRwDBConn, aesEncryption, mobileLogger)

		// new module for mobile service
		mobileComponent := mobile.NewComponent(keycloakClient, configDBModule, usersDBModule, technicalTokenProvider, authorizationManager, mobileLogger)
		mobileComponent = mobile.MakeAuthorizationMobileComponentMW(log.With(mobileLogger, "mw", "endpoint"))(mobileComponent)

		var rateLimitMobile = rateLimit[RateKeyMobile]
		mobileEndpoints = mobile.Endpoints{
			GetUserInformation: prepareEndpoint(mobile.MakeGetUserInformationEndpoint(mobileComponent), "get_user_information", influxMetrics, mobileLogger, tracer, rateLimitMobile),
		}
	}

	// Register service.
	var registerEndpoints register.Endpoints
	{
		var registerLogger = log.With(logger, "svc", "register")

		// Configure events db module
		eventsDBModule := database.NewEventsDBModule(eventsDBConn)

		// module for storing and retrieving the custom configuration
		var configDBModule = createConfigurationDBModule(configurationRwDBConn, influxMetrics, registerLogger)

		// module for storing and retrieving details of the self-registered users
		var usersDBModule = keycloakb.NewUsersDetailsDBModule(usersRwDBConn, aesEncryption, registerLogger)

		// module for onboarding process
		var onboardingModule = keycloakb.NewOnboardingModule(keycloakClient, keycloakConfig.URIProvider, registerLogger)

		registerComponent := register.NewComponent(keycloakClient, technicalTokenProvider, usersDBModule, configDBModule, eventsDBModule, onboardingModule, glnVerifier, registerLogger)
		registerComponent = register.MakeAuthorizationRegisterComponentMW(log.With(registerLogger, "mw", "endpoint"))(registerComponent)

		var rateLimitRegister = rateLimit[RateKeyRegister]
		registerEndpoints = register.Endpoints{
			RegisterUser:     prepareEndpoint(register.MakeRegisterUserEndpoint(registerComponent, registerRealm), "register_user", influxMetrics, registerLogger, tracer, rateLimitRegister),
			RegisterCorpUser: prepareEndpoint(register.MakeRegisterCorpUserEndpoint(registerComponent), "register_corp_user", influxMetrics, registerLogger, tracer, rateLimitRegister),
			GetConfiguration: prepareEndpoint(register.MakeGetConfigurationEndpoint(registerComponent), "get_configuration", influxMetrics, registerLogger, tracer, rateLimitRegister),
		}

	}

	// Tools for endpoint middleware
	var idRetriever = keycloakb.NewRealmIDRetriever(keycloakClient)
	var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, logger)
	var endpointPhysicalCheckAvailabilityChecker = middleware.NewEndpointAvailabilityChecker(configuration.CheckKeyPhysical, idRetriever, configurationReaderDBModule)

	// KYC service.
	var kycEndpoints kyc.Endpoints
	{
		var kycLogger = log.With(logger, "svc", "kyc")

		// Configure events db module
		eventsDBModule := database.NewEventsDBModule(eventsDBConn)

		// module for storing and retrieving details of the users
		var usersDBModule = keycloakb.NewUsersDetailsDBModule(usersRwDBConn, aesEncryption, kycLogger)

		// module for archiving users
		var archiveDBModule = keycloakb.NewArchiveDBModule(archiveRwDBConn, archiveAesEncryption, kycLogger)

		// config
		var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, kycLogger)

		// accreditations module
		var accredsModule keycloakb.AccreditationsModule
		{
			accredsModule = keycloakb.NewAccreditationsModule(keycloakClient, configurationReaderDBModule, kycLogger)
		}

		// new module for KYC service
		kycComponent := kyc.NewComponent(technicalTokenProvider, registerRealm, keycloakClient, usersDBModule, archiveDBModule, configurationReaderDBModule, eventsDBModule, accredsModule, glnVerifier, kycLogger)
		kycComponent = kyc.MakeAuthorizationRegisterComponentMW(registerRealm, authorizationManager, endpointPhysicalCheckAvailabilityChecker, log.With(kycLogger, "mw", "endpoint"))(kycComponent)

		var rateLimitKyc = rateLimit[RateKeyKYC]
		kycEndpoints = kyc.Endpoints{
			GetActions:                      prepareEndpoint(kyc.MakeGetActionsEndpoint(kycComponent), "register_get_actions", influxMetrics, kycLogger, tracer, rateLimitKyc),
			GetUserInSocialRealm:            prepareEndpoint(kyc.MakeGetUserInSocialRealmEndpoint(kycComponent), "get_user_in_social_realm", influxMetrics, kycLogger, tracer, rateLimitKyc),
			GetUserByUsernameInSocialRealm:  prepareEndpoint(kyc.MakeGetUserByUsernameInSocialRealmEndpoint(kycComponent), "get_user_by_username_in_social_realm", influxMetrics, kycLogger, tracer, rateLimitKyc),
			ValidateUserInSocialRealm:       prepareEndpoint(kyc.MakeValidateUserInSocialRealmEndpoint(kycComponent), "validate_user_in_social_realm", influxMetrics, kycLogger, tracer, rateLimitKyc),
			SendSMSConsentCodeInSocialRealm: prepareEndpoint(kyc.MakeSendSmsConsentCodeInSocialRealmEndpoint(kycComponent), "send_sms_consent_code_in_social_realm", influxMetrics, kycLogger, tracer, rateLimitKyc),
			SendSMSCodeInSocialRealm:        prepareEndpoint(kyc.MakeSendSmsCodeInSocialRealmEndpoint(kycComponent), "send_sms_code_in_social_realm", influxMetrics, kycLogger, tracer, rateLimitKyc),
			GetUser:                         prepareEndpoint(kyc.MakeGetUserEndpoint(kycComponent), "get_user", influxMetrics, kycLogger, tracer, rateLimitKyc),
			GetUserByUsername:               prepareEndpoint(kyc.MakeGetUserByUsernameEndpoint(kycComponent), "get_user_by_username", influxMetrics, kycLogger, tracer, rateLimitKyc),
			ValidateUser:                    prepareEndpoint(kyc.MakeValidateUserEndpoint(kycComponent), "validate_user", influxMetrics, kycLogger, tracer, rateLimitKyc),
			SendSMSConsentCode:              prepareEndpoint(kyc.MakeSendSmsConsentCodeEndpoint(kycComponent), "send_sms_consent_code", influxMetrics, kycLogger, tracer, rateLimitKyc),
			SendSMSCode:                     prepareEndpoint(kyc.MakeSendSmsCodeEndpoint(kycComponent), "send_sms_code", influxMetrics, kycLogger, tracer, rateLimitKyc),
		}
	}

	// Export configuration
	var exportModule = export.NewModule(keycloakClient, logger)
	var cfgStorageModule = export.NewConfigStorageModule(eventsDBConn)

	var exportComponent = export.NewComponent(keycloakb.ComponentName, keycloakb.Version, logger, exportModule, cfgStorageModule)
	var exportEndpoint = export.MakeExportEndpoint(exportComponent)
	var exportSaveAndExportEndpoint = export.MakeStoreAndExportEndpoint(exportComponent)

	// HTTP Monitoring (For monitoring probes, ...).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrMonitoring)

		var route = mux.NewRouter()
		var limiter = rate.NewLimiter(rate.Every(time.Second), rateLimit[RateKeyMonitoring])

		route.Handle("/", commonhttp.MakeVersionHandler(keycloakb.ComponentName, ComponentID, keycloakb.Version, Environment, GitCommit))
		route.Handle(pathHealthCheck, healthChecker.MakeHandler(limiter))

		errc <- http.ListenAndServe(httpAddrMonitoring, route)
	}()

	// HTTP Internal Call Server (Export, Communications & Validation API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrInternal)

		var route = mux.NewRouter()

		// Export.
		route.Handle("/export", export.MakeHTTPExportHandler(exportEndpoint)).Methods("GET")
		route.Handle("/export", export.MakeHTTPExportHandler(exportSaveAndExportEndpoint)).Methods("POST")

		// Validation
		var getUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.GetUser)
		var updateUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.UpdateUser)
		var createCheckHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.CreateCheck)
		var createPendingCheckHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.CreatePendingCheck)
		var deletePendingCheckHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, tracer, logger)(validationEndpoints.DeletePendingCheck)

		var validationSubroute = route.PathPrefix("/validation").Subrouter()

		validationSubroute.Path("/realms/{realm}/users/{userID}").Methods("GET").Handler(getUserHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}").Methods("PUT").Handler(updateUserHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}/checks").Methods("POST").Handler(createCheckHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}/checks/pending").Methods("POST").Handler(createPendingCheckHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}/checks/pending/{pendingCheck}").Methods("DELETE").Handler(deletePendingCheckHandler)

		// Communications
		var sendMailHandler = configureCommunicationsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(communicationsEndpoints.SendEmail)
		var sendSMSHandler = configureCommunicationsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(communicationsEndpoints.SendSMS)

		var communicationsSubroute = route.PathPrefix("/communications").Subrouter()

		communicationsSubroute.Path("/realms/{realm}/send-mail").Methods("POST").Handler(sendMailHandler)
		communicationsSubroute.Path("/realms/{realm}/send-sms").Methods("POST").Handler(sendSMSHandler)

		// Tasks
		var deniedToUUsersHandler = configureTasksHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(tasksEndpoints.DeleteDeniedToUUsers)

		route.PathPrefix("/tasks/denied-terms-of-use-users").Methods("DELETE").Handler(deniedToUUsersHandler)

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

		// Rights
		var rightsHandler = configureRightsHandler(keycloakb.ComponentName, ComponentID, idGenerator, authorizationManager, keycloakClient, audienceRequired, tracer, logger)
		route.Path("/rights").Methods("GET").Handler(rightsHandler)

		// Statistics
		var getStatisticsActionsHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetActions)
		var getStatisticsHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatistics)
		var getStatisticsIdentificationsHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsIdentifications)
		var getStatisticsUsersHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsUsers)
		var getStatisticsAuthenticatorsHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsAuthenticators)
		var getStatisticsAuthenticationsHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsAuthentications)
		var getStatisticsAuthenticationsLogHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetStatisticsAuthenticationsLog)
		var getMigrationReportHandler = configureStatisticsHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(statisticsEndpoints.GetMigrationReport)

		route.Path("/statistics/actions").Methods("GET").Handler(getStatisticsActionsHandler)
		route.Path("/statistics/realms/{realm}").Methods("GET").Handler(getStatisticsHandler)
		route.Path("/statistics/realms/{realm}/identifications").Methods("GET").Handler(getStatisticsIdentificationsHandler)
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
		var lockUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.LockUser)
		var unlockUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.UnlockUser)
		var deleteUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteUser)
		var getUsersHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUsers)
		var getRolesForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetRolesOfUser)
		var addRoleToUser = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.AddRoleToUser)
		var deleteRoleForUser = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteRoleForUser)
		var getGroupsForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetGroupsOfUser)
		var addGroupToUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.AddGroupToUser)
		var deleteGroupForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteGroupForUser)
		var getUserChecksHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUserChecks)
		var getUserAccountStatusHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUserAccountStatus)
		var getUserAccountStatusByEmailHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetUserAccountStatusByEmail)
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
		var sendSmsCodeHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SendSmsCode)
		var sendOnboardingEmail = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SendOnboardingEmail)
		var sendReminderEmailHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.SendReminderEmail)
		var resetSmsCounterHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ResetSmsCounter)
		var createRecoveryCodeHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateRecoveryCode)
		var createActivationCodeHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.CreateActivationCode)

		var getCredentialsForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.GetCredentialsForUser)
		var deleteCredentialsForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.DeleteCredentialsForUser)
		var resetCredentialFailuresForUserHandler = configureManagementHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, logger)(managementEndpoints.ResetCredentialFailuresForUser)
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
		managementSubroute.Path("/realms/{realm}/users/status").Methods("GET").Handler(getUserAccountStatusByEmailHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("GET").Handler(getUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("PUT").Handler(updateUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}").Methods("DELETE").Handler(deleteUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/lock").Methods("PUT").Handler(lockUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/unlock").Methods("PUT").Handler(unlockUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/groups").Methods("GET").Handler(getGroupsForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/groups/{groupID}").Methods("POST").Handler(addGroupToUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/groups/{groupID}").Methods("DELETE").Handler(deleteGroupForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/roles").Methods("GET").Handler(getRolesForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/roles/{roleID}").Methods("POST").Handler(addRoleToUser)
		managementSubroute.Path("/realms/{realm}/users/{userID}/roles/{roleID}").Methods("DELETE").Handler(deleteRoleForUser)
		managementSubroute.Path("/realms/{realm}/users/{userID}/checks").Methods("GET").Handler(getUserChecksHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/status").Methods("GET").Handler(getUserAccountStatusHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/trustIdGroups").Methods("GET").Handler(getTrustIDGroupsOfUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/trustIdGroups").Methods("PUT").Handler(setTrustIDGroupsToUserHandler)

		// role mappings
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("GET").Handler(getClientRoleForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("POST").Handler(addClientRoleToUserHandler)

		managementSubroute.Path("/realms/{realm}/users/{userID}/reset-password").Methods("PUT").Handler(resetPasswordHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/execute-actions-email").Methods("PUT").Handler(executeActionsEmailHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-sms-code").Methods("POST").Handler(sendSmsCodeHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-onboarding-email").Methods("POST").Handler(sendOnboardingEmail)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-reminder-email").Methods("POST").Handler(sendReminderEmailHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/reset-sms-counter").Methods("PUT").Handler(resetSmsCounterHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/recovery-code").Methods("POST").Handler(createRecoveryCodeHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/activation-code").Methods("POST").Handler(createActivationCodeHandler)

		// Credentials
		managementSubroute.Path("/realms/{realm}/users/{userID}/credentials").Methods("GET").Handler(getCredentialsForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/credentials/{credentialID}").Methods("DELETE").Handler(deleteCredentialsForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/credentials/{credentialID}/reset-failures").Methods("PUT").Handler(resetCredentialFailuresForUserHandler)

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

		// KYC handlers
		var kycGetActionsHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.GetActions)
		var kycGetUserInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUserInSocialRealm)
		var kycGetUserByUsernameInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUserByUsernameInSocialRealm)
		var kycValidateUserInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.ValidateUserInSocialRealm)
		var kycSendSMSConsentCodeInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSConsentCodeInSocialRealm)
		var kycSendSMSCodeInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSCodeInSocialRealm)
		var kycGetUserHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUser)
		var kycGetUserByUsernameHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUserByUsername)
		var kycValidateUserHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.ValidateUser)
		var kycSendSMSConsentCodeHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSConsentCode)
		var kycSendSMSCodeHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tracer, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSCode)

		// KYC methods
		route.Path("/kyc/actions").Methods("GET").Handler(kycGetActionsHandler)
		route.Path("/kyc/social/users").Methods("GET").Handler(kycGetUserByUsernameInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}").Methods("GET").Handler(kycGetUserInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}").Methods("PUT").Handler(kycValidateUserInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}/send-consent-code").Methods("POST").Handler(kycSendSMSConsentCodeInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}/send-sms-code").Methods("POST").Handler(kycSendSMSCodeInSocialRealmHandler)
		route.Path("/kyc/realms/{realm}/users").Methods("GET").Handler(kycGetUserByUsernameHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}").Methods("GET").Handler(kycGetUserHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}").Methods("PUT").Handler(kycValidateUserHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}/send-consent-code").Methods("POST").Handler(kycSendSMSConsentCodeHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}/send-sms-code").Methods("POST").Handler(kycSendSMSCodeHandler)

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

	// HTTP Mobile self-service Server (Mobile API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrMobile)

		var route = mux.NewRouter()

		// Mobile
		var getUserInfoHandler = configureMobileHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, mobileAudienceRequired, tracer, logger)(mobileEndpoints.GetUserInformation)

		route.Path("/mobile/userinfo").Methods("GET").Handler(getUserInfoHandler)

		var handler http.Handler = route

		if accessLogsEnabled {
			handler = commonhttp.MakeAccessLogHandler(accessLogger, handler)
		}

		c := cors.New(corsOptions)
		handler = c.Handler(handler)

		errc <- http.ListenAndServe(httpAddrMobile, handler)
	}()

	// HTTP register Server (Register API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrRegister)

		var route = mux.NewRouter()

		// Configuration
		var getConfigurationHandler = configurePublicRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, tracer, logger)(registerEndpoints.GetConfiguration)

		// Handler with recaptcha token
		var registerUserHandler = configureRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, recaptchaURL, recaptchaSecret, tracer, logger)(registerEndpoints.RegisterUser)
		route.Path("/register/user").Methods("POST").Handler(registerUserHandler)

		// Handler with recaptcha token
		var registerCorpUserHandler = configureRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, recaptchaURL, recaptchaSecret, tracer, logger)(registerEndpoints.RegisterCorpUser)
		route.Path("/register/realms/{corpRealm}/user").Methods("POST").Handler(registerCorpUserHandler)

		route.Path("/register/config").Methods("GET").Handler(getConfigurationHandler)

		var handler http.Handler = route

		if accessLogsEnabled {
			handler = commonhttp.MakeAccessLogHandler(accessLogger, handler)
		}

		c := cors.New(corsOptions)
		handler = c.Handler(handler)

		errc <- http.ListenAndServe(httpAddrRegister, handler)
	}()

	// Influx writing.
	go func() {
		var tic = time.NewTicker(influxWriteInterval)
		defer tic.Stop()
		influxMetrics.WriteLoop(tic.C)
	}()

	logger.Info(ctx, "msg", "Started")
	logger.Error(ctx, "err", <-errc)
}

func config(ctx context.Context, logger log.Logger) *viper.Viper {
	logger.Info(ctx, "msg", "load configuration and command args")

	var v = viper.New()

	// Component default.
	v.SetDefault(cfgConfigFile, "./configs/keycloak_bridge.yml")

	// Log level
	v.SetDefault(cfgLogLevel, "info")

	// Access Logs
	v.SetDefault(cfgAccessLogsEnabled, true)

	// Publishing
	v.SetDefault(cfgHTTPAddrInternal, defaultPublishingIP+":8888")
	v.SetDefault(cfgHTTPAddrManagement, defaultPublishingIP+":8877")
	v.SetDefault(cfgHTTPAddrAccount, defaultPublishingIP+":8866")
	v.SetDefault(cfgHTTPAddrRegister, defaultPublishingIP+":8855")
	v.SetDefault(cfgHTTPAddrMobile, defaultPublishingIP+":8844")
	v.SetDefault(cfgHTTPAddrMonitoring, defaultPublishingIP+":8899")

	// Security - Audience check
	v.SetDefault(cfgAudienceRequired, "")
	v.SetDefault(cfgMobileAudienceRequired, "")
	v.SetDefault(cfgTrustIDGroups,
		[]string{
			"l1_support_agent",
			"registration_officer",
			"end_user"})
	v.SetDefault(cfgValidationBasicAuthToken, "")

	//Encryption key
	v.SetDefault(cfgDbAesGcmTagSize, 16)
	v.SetDefault(cfgDbAesGcmKey, "")
	v.SetDefault(cfgDbArchiveAesGcmTagSize, 16)
	v.SetDefault(cfgDbArchiveAesGcmKey, "")

	// CORS configuration
	v.SetDefault(cfgAllowedOrigins, []string{})
	v.SetDefault(cfgAllowedMethods, []string{})
	v.SetDefault(cfgAllowCredentials, true)
	v.SetDefault(cfgAllowedHeaders, []string{})
	v.SetDefault(cfgExposedHeaders, []string{})
	v.SetDefault(cfgDebug, false)

	// Keycloak default.
	v.SetDefault(cfgAddrAPI, "http://127.0.0.1:8080")
	v.SetDefault(cfgAddrTokenProviderMap, map[string]string{"default": "http://127.0.0.1:8080", "_local": "http://localhost:8080"})
	v.SetDefault(cfgTimeout, "5s")

	// Storage events in DB (read/write)
	database.ConfigureDbDefault(v, cfgAuditRwDbParams, "CT_BRIDGE_DB_AUDIT_RW_USERNAME", "CT_BRIDGE_DB_AUDIT_RW_PASSWORD")
	v.SetDefault(cfgAuditRwDbParams+"-enabled", false)

	// Storage events in DB (read only)
	database.ConfigureDbDefault(v, cfgAuditRoDbParams, "CT_BRIDGE_DB_AUDIT_RO_USERNAME", "CT_BRIDGE_DB_AUDIT_RO_PASSWORD")

	//Storage custom configuration in DB (read/write)
	database.ConfigureDbDefault(v, cfgConfigRwDbParams, "CT_BRIDGE_DB_CONFIG_RW_USERNAME", "CT_BRIDGE_DB_CONFIG_RW_PASSWORD")

	//Storage custom configuration in DB (read only)
	database.ConfigureDbDefault(v, cfgConfigRoDbParams, "CT_BRIDGE_DB_CONFIG_RO_USERNAME", "CT_BRIDGE_DB_CONFIG_RO_PASSWORD")

	//Storage users in DB (read/write)
	database.ConfigureDbDefault(v, cfgUsersRwDbParams, "CT_BRIDGE_DB_USERS_RW_USERNAME", "CT_BRIDGE_DB_USERS_RW_PASSWORD")

	//Storage archive in DB (read only)
	database.ConfigureDbDefault(v, cfgArchiveRwDbParams, "CT_BRIDGE_DB_ARCHIVE_RW_USERNAME", "CT_BRIDGE_DB_ARCHIVE_RW_PASSWORD")

	// Rate limiting (in requests/second)
	v.SetDefault(cfgRateKeyValidation, 1000)
	v.SetDefault(cfgRateKeyCommunications, 1000)
	v.SetDefault(cfgRateKeyAccount, 1000)
	v.SetDefault(cfgRateKeyMobile, 1000)
	v.SetDefault(cfgRateKeyMonitoring, 1000)
	v.SetDefault(cfgRateKeyManagement, 1000)
	v.SetDefault(cfgRateKeyManagementStatus, 3)
	v.SetDefault(cfgRateKeyStatistics, 1000)
	v.SetDefault(cfgRateKeyEvents, 1000)
	v.SetDefault(cfgRateKeyRegister, 1000)
	v.SetDefault(cfgRateKeyTasks, 10)
	v.SetDefault(cfgRateKeyKYC, 1000)

	// Influx DB client default.
	v.SetDefault("influx", false)
	v.SetDefault("influx-host-port", "")
	v.SetDefault("influx-username", "")
	v.SetDefault("influx-password", "")
	v.SetDefault("influx-database", "")
	v.SetDefault("influx-precision", "")
	v.SetDefault("influx-retention-policy", "")
	v.SetDefault("influx-write-consistency", "")
	v.SetDefault(cfgInfluxWriteInterval, "1s")

	// Sentry client default.
	v.SetDefault("sentry", false)
	v.SetDefault(cfgSentryDsn, "")

	// Jaeger tracing default.
	v.SetDefault("jaeger", false)
	v.SetDefault("jaeger-sampler-type", "")
	v.SetDefault("jaeger-sampler-param", 0)
	v.SetDefault("jaeger-sampler-host-port", "")
	v.SetDefault("jaeger-reporter-logspan", false)
	v.SetDefault("jaeger-write-interval", "1s")

	// Debug routes enabled.
	v.SetDefault(cfgPprofRouteEnabled, true)

	// Liveness probe
	v.SetDefault("livenessprobe-http-timeout", 900)
	v.SetDefault("livenessprobe-cache-duration", 500)

	// Register parameters
	v.SetDefault(cfgRegisterRealm, "trustid")
	v.SetDefault(cfgRecaptchaURL, "https://www.google.com/recaptcha/api/siteverify")
	v.SetDefault(cfgRecaptchaSecret, "")

	// Register parameters
	v.SetDefault(cfgTechnicalRealm, "master")
	v.SetDefault(cfgTechnicalUsername, "")
	v.SetDefault(cfgTechnicalPassword, "")
	v.SetDefault(cfgTechnicalClientID, "admin-cli")

	// Max lifespan
	v.SetDefault(cfgMaxLifeSpan, "168h")

	// GLN
	v.SetDefault(cfgGlnRefDataEnabled, true)
	v.SetDefault(cfgGlnRefDataURI, "https://refdatabase.refdata.ch/Service/Partner.asmx")
	v.SetDefault(cfgGlnRefDataTimeout, "10s")
	v.SetDefault(cfgGlnNaRegEnabled, false)
	v.SetDefault(cfgGlnNaRegURI, "https://www.nareg.ch")
	v.SetDefault(cfgGlnNaRegTimeout, "10s")
	v.SetDefault(cfgGlnPsyRegEnabled, false)
	v.SetDefault(cfgGlnPsyRegURI, "https://ws.psyreg.bag.admin.ch")
	v.SetDefault(cfgGlnPsyRegTimeout, "10s")
	v.SetDefault(cfgGlnMedRegEnabled, false)
	v.SetDefault(cfgGlnMedRegURI, "https://www.medregom.admin.ch")
	v.SetDefault(cfgGlnMedRegTimeout, "10s")

	// First level of override.
	pflag.String(cfgConfigFile, v.GetString(cfgConfigFile), "The configuration file path can be relative or absolute.")
	v.BindPFlag(cfgConfigFile, pflag.Lookup(cfgConfigFile))
	pflag.Parse()

	// Bind ENV variables
	// We use env variables to bind Openshift secrets
	var censoredParameters = map[string]bool{}

	v.BindEnv(cfgRecaptchaSecret, "CT_BRIDGE_RECAPTCHA_SECRET")
	censoredParameters[cfgRecaptchaSecret] = true

	v.BindEnv(cfgTechnicalUsername, "CT_BRIDGE_TECHNICAL_USERNAME")
	v.BindEnv(cfgTechnicalPassword, "CT_BRIDGE_TECHNICAL_PASSWORD")
	censoredParameters[cfgTechnicalPassword] = true

	v.BindEnv("influx-username", "CT_BRIDGE_INFLUX_USERNAME")
	v.BindEnv("influx-password", "CT_BRIDGE_INFLUX_PASSWORD")
	censoredParameters["influx-password"] = true

	v.BindEnv(cfgSentryDsn, "CT_BRIDGE_SENTRY_DSN")
	censoredParameters[cfgSentryDsn] = true

	v.BindEnv(cfgValidationBasicAuthToken, "CT_BRIDGE_VALIDATION_BASIC_AUTH")
	censoredParameters[cfgValidationBasicAuthToken] = true

	v.BindEnv(cfgDbAesGcmKey, "CT_BRIDGE_DB_AES_KEY")
	censoredParameters[cfgDbAesGcmKey] = true

	v.BindEnv(cfgDbArchiveAesGcmKey, "CT_BRIDGE_DB_ARCHIVE_AES_KEY")
	censoredParameters[cfgDbArchiveAesGcmKey] = true

	// Load and log config.
	v.SetConfigFile(v.GetString(cfgConfigFile))
	var err = v.ReadInConfig()
	if err != nil {
		logger.Error(ctx, "err", err)
	}

	// If the host/port is not set, we consider the components deactivated.
	v.Set("influx", v.GetString("influx-host-port") != "")
	v.Set("sentry", v.GetString(cfgSentryDsn) != "")
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

func configureStatisticsHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
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

func configureMobileHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = mobile.MakeMobileHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureKYCHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client,
	audienceRequired string, tracer tracing.OpentracingClient, availabilityChecker middleware.EndpointAvailabilityChecker,
	verifyAvailableChecks bool, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = kyc.MakeKYCHandler(endpoint, logger)
		if verifyAvailableChecks {
			handler = middleware.MakeEndpointAvailableCheckMW(availabilityChecker, logger)(handler)
		}
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureRegisterHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, recaptchaURL, recaptchaSecret string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
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

func configureCommunicationsHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = communications.MakeCommunicationsHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

func configureTasksHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, tracer tracing.OpentracingClient, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = tasks.MakeTasksHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, tracer, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
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
