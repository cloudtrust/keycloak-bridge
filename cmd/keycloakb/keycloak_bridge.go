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

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database"
	"github.com/cloudtrust/common-service/v2/database/sqltypes"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	csevents "github.com/cloudtrust/common-service/v2/events"
	"github.com/cloudtrust/common-service/v2/healthcheck"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/idgenerator"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/middleware"
	"github.com/cloudtrust/common-service/v2/security"
	"github.com/cloudtrust/httpclient"
	kafkauniverse "github.com/cloudtrust/kafka-client"
	"github.com/cloudtrust/keycloak-bridge/internal/business"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/idnowclient"
	"github.com/cloudtrust/keycloak-bridge/internal/profile"
	"github.com/cloudtrust/keycloak-bridge/pkg/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications"
	conf "github.com/cloudtrust/keycloak-bridge/pkg/configuration"
	"github.com/cloudtrust/keycloak-bridge/pkg/idp"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc"
	"github.com/cloudtrust/keycloak-bridge/pkg/management"
	mobile "github.com/cloudtrust/keycloak-bridge/pkg/mobile"
	"github.com/cloudtrust/keycloak-bridge/pkg/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/support"
	"github.com/cloudtrust/keycloak-bridge/pkg/tasks"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation"
	keycloak "github.com/cloudtrust/keycloak-client/v2"
	keycloakapi "github.com/cloudtrust/keycloak-client/v2/api"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
	kit_log "github.com/go-kit/log"
	kit_level "github.com/go-kit/log/level"
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
	pathHealthLive      = "/health/live"

	RateKeyAccount          = iota
	RateKeyCommunications   = iota
	RateKeyKYC              = iota
	RateKeyManagement       = iota
	RateKeyManagementStatus = iota
	RateKeyMobile           = iota
	RateKeyMonitoring       = iota
	RateKeyRegister         = iota
	RateKeyStatistics       = iota
	RateKeySupport          = iota
	RateKeyTasks            = iota
	RateKeyValidation       = iota
	RateKeyIDP              = iota

	cfgConfigFile               = "config-file"
	cfgHTTPAddrInternal         = "internal-http-host-port"
	cfgHTTPAddrManagement       = "management-http-host-port"
	cfgHTTPAddrAccount          = "account-http-host-port"
	cfgHTTPAddrRegister         = "register-http-host-port"
	cfgHTTPAddrMobile           = "mobile-http-host-port"
	cfgHTTPAddrMonitoring       = "monitoring-http-host-port"
	cfgHTTPAddrConfiguration    = "configuration-http-host-port"
	cfgAddrAccounting           = "accounting-api-uri"
	cfgAccountingTimeout        = "accounting-timeout"
	cfgAudienceRequired         = "audience-required"
	cfgMobileAudienceRequired   = "mobile-audience-required"
	cfgValidationBasicAuthToken = "validation-basic-auth-token"
	cfgPprofRouteEnabled        = "pprof-route-enabled"
	cfgConfigRwDbParams         = "db-config-rw"
	cfgConfigRoDbParams         = "db-config-ro"
	cfgRateKeyValidation        = "rate-validation"
	cfgRateKeyCommunications    = "rate-communications"
	cfgRateKeyAccount           = "rate-account"
	cfgRateKeyMobile            = "rate-mobile"
	cfgRateKeyMonitoring        = "rate-monitoring"
	cfgRateKeyManagement        = "rate-management"
	cfgRateKeyManagementStatus  = "rate-management-status"
	cfgRateKeyStatistics        = "rate-statistics"
	cfgRateKeyRegister          = "rate-register"
	cfgRateKeySupport           = "rate-support"
	cfgRateKeyTasks             = "rate-tasks"
	cfgRateKeyKYC               = "rate-kyc"
	cfgRateKeyIDP               = "rate-idp"
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
	cfgRegisterMaxInactiveLock  = "register-inactive-lock-duration"
	cfgTechnicalRealm           = "technical-realm"
	cfgTechnicalUsername        = "technical-username"
	cfgTechnicalPassword        = "technical-password"
	cfgTechnicalClientID        = "technical-client-id"
	cfgRecaptchaURL             = "recaptcha-url"
	cfgRecaptchaSecret          = "recaptcha-secret"
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
	cfgValidationRules          = "validation-rules"
	cfgOnboardingRealmOverrides = "onboarding-realm-overrides"
	cfgAddrAccreditations       = "accreditations-api-uri"
	cfgAccreditationsTimeout    = "accreditations-timeout"
	cfgAddrIdnow                = "idnow-service-api-uri"
	cfgIdnowTimeout             = "idnow-service-timeout"
	cfgContextKeys              = "context-keys"
	cfgLogEventRate             = "log-events-rate"

	// Kafka
	kafkaReloadAuthProducer = "auth-reload-producer"
	kafkaReloadAuthConsumer = "auth-reload-consumer"
	kafkaEventProducer      = "event-producer"

	// HRD
	cfgHrd = "hrd"
)

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
		httpAddrInternal      = c.GetString(cfgHTTPAddrInternal)
		httpAddrManagement    = c.GetString(cfgHTTPAddrManagement)
		httpAddrAccount       = c.GetString(cfgHTTPAddrAccount)
		httpAddrRegister      = c.GetString(cfgHTTPAddrRegister)
		httpAddrMobile        = c.GetString(cfgHTTPAddrMobile)
		httpAddrMonitoring    = c.GetString(cfgHTTPAddrMonitoring)
		httpAddrConfiguration = c.GetString(cfgHTTPAddrConfiguration)

		// Enabled units
		pprofRouteEnabled = c.GetBool(cfgPprofRouteEnabled)

		// DB for custom configuration
		configRwDbParams = database.GetDbConfig(c, cfgConfigRwDbParams)
		configRoDbParams = database.GetDbConfig(c, cfgConfigRoDbParams)

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
			RateKeyRegister:         c.GetInt(cfgRateKeyRegister),
			RateKeySupport:          c.GetInt(cfgRateKeySupport),
			RateKeyTasks:            c.GetInt(cfgRateKeyTasks),
			RateKeyKYC:              c.GetInt(cfgRateKeyKYC),
			RateKeyIDP:              c.GetInt(cfgRateKeyIDP),
		}

		corsOptions = cors.Options{
			AllowedOrigins:   c.GetStringSlice(cfgAllowedOrigins),
			AllowedMethods:   c.GetStringSlice(cfgAllowedMethods),
			AllowCredentials: c.GetBool(cfgAllowCredentials),
			AllowedHeaders:   c.GetStringSlice(cfgAllowedHeaders),
			ExposedHeaders:   c.GetStringSlice(cfgExposedHeaders),
			Debug:            c.GetBool(cfgDebug),
		}

		logLevel     = c.GetString(cfgLogLevel)
		logEventRate = c.GetInt64(cfgLogEventRate)

		// Access logs
		accessLogsEnabled = c.GetBool(cfgAccessLogsEnabled)

		// Register parameters
		registerRealm                = c.GetString(cfgRegisterRealm)
		recaptchaURL                 = c.GetString(cfgRecaptchaURL)
		recaptchaSecret              = c.GetString(cfgRecaptchaSecret)
		registerInactiveLockDuration = c.GetDuration(cfgRegisterMaxInactiveLock)

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

		// Onboarding realm overrides
		onboardingRealmOverrides = c.GetStringMapString(cfgOnboardingRealmOverrides)
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
	archiveAesEncryption, err := security.NewAesGcmEncrypterFromBase64(c.GetString(cfgDbArchiveAesGcmKey), c.GetInt(cfgDbArchiveAesGcmTagSize))
	if err != nil {
		logger.Error(ctx, "msg", "could not create AES-GCM encrypting tool instance (archive)", "err", err)
		return
	}

	// Security - allowed trustID groups
	var trustIDGroups = c.GetStringSlice(cfgTrustIDGroups)

	// Keycloak
	var keycloakConfig keycloak.Config
	{
		keycloakConfig, err = toolbox.NewConfig(func(value any) error {
			return c.UnmarshalKey("keycloak", value)
		})
		if err != nil {
			logger.Error(ctx, "msg", "could not get Keycloak configuration", "err", err)
			return
		}
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

	var configurationRwDBConn sqltypes.CloudtrustDB
	{
		var err error
		configurationRwDBConn, err = database.NewReconnectableCloudtrustDB(configRwDbParams, toDbLogger(logger, configRwDbParams))
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for configuration storage (RW)", "err", err)
			return
		}
	}

	var configurationRoDBConn sqltypes.CloudtrustDB
	{
		var err error
		configurationRoDBConn, err = database.NewReconnectableCloudtrustDB(configRoDbParams, toDbLogger(logger, configRoDbParams))
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for configuration storage (RO)", "err", err)
			return
		}
	}

	var archiveRwDBConn sqltypes.CloudtrustDB
	{
		var err error
		archiveRwDBConn, err = database.NewReconnectableCloudtrustDB(archiveRwDbParams, toDbLogger(logger, archiveRwDbParams))
		if err != nil {
			logger.Error(ctx, "msg", "could not create DB connection for archive (RW)", "err", err)
			return
		}
	}

	// Create technical OIDC token provider and validate technical user credentials
	var technicalTokenProvider toolbox.OidcTokenProvider
	{
		technicalTokenProvider = toolbox.NewOidcTokenProvider(keycloakConfig, technicalRealm, technicalUsername, technicalPassword, technicalClientID, logger)
		keycloakConfig.URIProvider.ForEachContextURI(func(realm, _, _ string) {
			if _, err := technicalTokenProvider.ProvideTokenForRealm(context.Background(), realm); err != nil {
				logger.Warn(context.Background(), "msg", "OIDC token provider validation failed for technical user", "err", err.Error(), "realm", realm)
			}
		})
	}

	// Users profile cache
	profileCache := toolbox.NewUserProfileCache(keycloakClient, technicalTokenProvider)

	// Actions allowed in Authorization Manager
	var authActions = security.Actions.GetActionNamesForService(security.BridgeService)
	authActions = mobile.AppendIDNowActions(authActions)

	// Tools for authorization manager
	var authorizationLogger = log.With(logger, "svc", "authorization")
	var authConfigurationReaderDBModule *configuration.ConfigurationReaderDBModule
	{
		authConfigurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, authorizationLogger, authActions)
	}

	// Authorization Manager
	var authorizationManager security.AuthorizationManager
	{
		var err error
		authorizationManager, err = security.NewAuthorizationManager(authConfigurationReaderDBModule, commonKcAdaptor, authorizationLogger)
		if err != nil {
			logger.Error(ctx, "msg", "could not load authorizations", "err", err)
			return
		}
	}

	var roleBasedAuthorizationManager = security.NewRoleBasedAuthorizationManager(authConfigurationReaderDBModule, commonKcAdaptor, authorizationLogger)

	// Kafka
	var kafkaUniverse *kafkauniverse.KafkaUniverse
	{
		var kafkaLogger = log.With(logger, "svc", "kafka")

		var err error
		kafkaUniverse, err = kafkauniverse.NewKafkaUniverse(ctx, kafkaLogger, "CT_KAFKA_", func(value any) error {
			return c.UnmarshalKey("kafka", value)
		})
		if err != nil {
			kafkaLogger.Error(ctx, "msg", "could not configure Kafka", "err", err)
			return
		}
		logger.Info(ctx, "msg", "Kafka configuration loaded")
	}
	defer kafkaUniverse.Close()

	if err := kafkaUniverse.InitializeConsumers(kafkaReloadAuthConsumer); err != nil {
		logger.Error(ctx, "msg", "can't initialize kafka producers", "err", err)
		return
	}

	var contextInitializer = func(ctx context.Context) context.Context {
		return context.WithValue(ctx, cs.CtContextCorrelationID, idGenerator.NextID())
	}

	kafkaUniverse.GetConsumer(kafkaReloadAuthConsumer).
		SetContextInitializer(contextInitializer).
		SetLogEventRate(logEventRate).
		SetHandler(func(ctx context.Context, message kafkauniverse.KafkaMessage) error {
			return authorizationManager.ReloadAuthorizations(ctx)
		})

	kafkaUniverse.StartConsumers(kafkaReloadAuthConsumer)

	if err := kafkaUniverse.InitializeProducers(kafkaReloadAuthProducer, kafkaEventProducer); err != nil {
		logger.Error(ctx, "msg", "can't initialize kafka producers", "err", err)
		return
	}

	authReloadProducer := kafkaUniverse.GetProducer(kafkaReloadAuthProducer)
	eventProducer := kafkaUniverse.GetProducer(kafkaEventProducer)

	// Health check configuration
	var healthChecker = healthcheck.NewHealthChecker(keycloakb.ComponentName, logger)
	var healthCheckCacheDuration = c.GetDuration("livenessprobe-cache-duration") * time.Millisecond
	var httpTimeout = c.GetDuration("livenessprobe-http-timeout") * time.Millisecond
	healthChecker.AddDatabase("Config R/W", configurationRwDBConn, healthCheckCacheDuration)
	healthChecker.AddDatabase("Config RO", configurationRoDBConn, healthCheckCacheDuration)
	healthChecker.AddDatabase("Archive RO", archiveRwDBConn, healthCheckCacheDuration)
	healthChecker.AddHTTPEndpoints(c.GetStringMapString("healthcheck-endpoints"), httpTimeout, 200, healthCheckCacheDuration)

	var livenessChecker = healthcheck.NewHealthChecker(keycloakb.ComponentName, logger)
	var livenessAuditTimeout = c.GetDuration("livenessprobe-audit-timeout") * time.Millisecond
	livenessChecker.AddAuditEventsReporterModule("Audit Events Reporter", csevents.NewAuditEventReporterModule(eventProducer, logger), livenessAuditTimeout, healthCheckCacheDuration)

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

	profile.GlnVerifier = glnVerifier

	var accreditationsService accreditationsclient.AccreditationsServiceClient
	{
		var httpClient, err = httpclient.NewBearerAuthClient(c.GetString(cfgAddrAccreditations), c.GetDuration(cfgAccreditationsTimeout), func() (string, error) {
			return technicalTokenProvider.ProvideTokenForRealm(context.TODO(), "master")
		})
		if err != nil {
			logger.Error(ctx, "msg", "could not initialize accreditations client", "err", err)
			return
		}
		// Accreditations service
		accreditationsService = accreditationsclient.MakeAccreditationsServiceClient(httpClient)
	}

	var idnowService idnowclient.IdnowServiceClient
	{
		var httpClient, err = httpclient.NewBearerAuthClient(c.GetString(cfgAddrIdnow), c.GetDuration(cfgIdnowTimeout), func() (string, error) {
			return technicalTokenProvider.ProvideTokenForRealm(context.TODO(), "master")
		})
		if err != nil {
			logger.Error(ctx, "msg", "could not initialize idnow service client", "err", err)
			return
		}
		// Accreditations service
		idnowService = idnowclient.MakeIdnowServiceClient(httpClient)
	}

	// Validation service.
	var validationEndpoints validation.Endpoints
	{
		var validationLogger = log.With(logger, "svc", "validation")

		// module to store validation events API calls
		auditEventsReporterModule := csevents.NewAuditEventReporterModule(eventProducer, validationLogger)

		// module for archiving users
		var archiveDBModule = keycloakb.NewArchiveDBModule(archiveRwDBConn, archiveAesEncryption, validationLogger)

		var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, validationLogger, authActions)

		validationComponent := validation.NewComponent(keycloakClient, technicalTokenProvider, archiveDBModule, auditEventsReporterModule, accreditationsService, configurationReaderDBModule, validationLogger)

		var rateLimitValidation = rateLimit[RateKeyValidation]
		validationEndpoints = validation.NewEndpoints(validationComponent, profileCache, func(endpoint cs.Endpoint, name string) endpoint.Endpoint {
			return prepareEndpoint(endpoint, name, validationLogger, rateLimitValidation)
		})
	}

	// Communications service.
	var communicationsEndpoints communications.Endpoints
	{
		var communicationsLogger = log.With(logger, "svc", "communications")

		communicationsComponent := communications.NewComponent(keycloakClient, technicalTokenProvider, communicationsLogger)
		// MakeAuthorizationCommunicationsComponentMW not called !!??

		var rateLimitCommunications = rateLimit[RateKeyCommunications]
		communicationsEndpoints = communications.Endpoints{
			SendEmail:       prepareEndpoint(communications.MakeSendEmailEndpoint(communicationsComponent), "send_email", communicationsLogger, rateLimitCommunications),
			SendEmailToUser: prepareEndpoint(communications.MakeSendEmailToUserEndpoint(communicationsComponent), "send_email_user", communicationsLogger, rateLimitCommunications),
			SendSMS:         prepareEndpoint(communications.MakeSendSMSEndpoint(communicationsComponent), "send_sms", communicationsLogger, rateLimitCommunications),
		}
	}

	// Tasks service.
	var tasksEndpoints tasks.Endpoints
	{
		var tasksLogger = log.With(logger, "svc", "tasks")

		// module to store validation events API calls
		auditEventsReporterModule := csevents.NewAuditEventReporterModule(eventProducer, tasksLogger)

		tasksComponent := tasks.NewComponent(keycloakClient, auditEventsReporterModule, tasksLogger)
		tasksComponent = tasks.MakeAuthorizationTasksComponentMW(log.With(tasksLogger, "mw", "endpoint"), authorizationManager)(tasksComponent)

		var rateLimitTasks = rateLimit[RateKeyTasks]
		tasksEndpoints = tasks.Endpoints{
			DeleteDeniedToUUsers: prepareEndpoint(tasks.MakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint(tasksComponent), "del_denied_tou_users", tasksLogger, rateLimitTasks),
		}
	}

	// Support service.
	var supportEndpoints support.Endpoints
	{
		var supportLogger = log.With(logger, "svc", "support")

		supportComponent := support.NewComponent(keycloakClient, supportLogger)

		var rateLimitSupport = rateLimit[RateKeySupport]
		supportEndpoints = support.Endpoints{
			GetSupportInformation: prepareEndpoint(support.MakeGetSupportInformationEndpoint(supportComponent), "get_email_information", supportLogger, rateLimitSupport),
		}
	}

	// Statistics service.
	var statisticsEndpoints statistics.Endpoints
	{
		var statisticsLogger = log.With(logger, "svc", "statistics")

		statisticsComponent := statistics.NewComponent(keycloakClient, accreditationsService, idnowService, statisticsLogger)
		statisticsComponent = statistics.MakeAuthorizationManagementComponentMW(log.With(statisticsLogger, "mw", "authorization"), authorizationManager)(statisticsComponent)

		var rateLimitStatistics = rateLimit[RateKeyStatistics]
		statisticsEndpoints = statistics.Endpoints{
			GetActions:                   prepareEndpoint(statistics.MakeGetActionsEndpoint(statisticsComponent), "get_actions", statisticsLogger, rateLimitStatistics),
			GetStatisticsIdentifications: prepareEndpoint(statistics.MakeGetStatisticsIdentificationsEndpoint(statisticsComponent), "get_statistics_identifications", statisticsLogger, rateLimitStatistics),
			GetStatisticsUsers:           prepareEndpoint(statistics.MakeGetStatisticsUsersEndpoint(statisticsComponent), "get_statistics_users", statisticsLogger, rateLimitStatistics),
			GetStatisticsAuthenticators:  prepareEndpoint(statistics.MakeGetStatisticsAuthenticatorsEndpoint(statisticsComponent), "get_statistics_authenticators", statisticsLogger, rateLimitStatistics),
			GetMigrationReport:           prepareEndpoint(statistics.MakeGetMigrationReportEndpoint(statisticsComponent), "get_migration_report", statisticsLogger, rateLimitStatistics),
		}
	}

	// Management service.
	var managementEndpoints = management.Endpoints{}
	{
		var managementLogger = log.With(logger, "svc", "management")

		// module to store API calls of the back office to the DB
		auditEventsReporterModule := csevents.NewAuditEventReporterModule(eventProducer, managementLogger)

		// module for storing and retrieving the custom configuration
		var configDBModule = createConfigurationDBModule(configurationRwDBConn, managementLogger)

		// module for onboarding process
		var onboardingModule = keycloakb.NewOnboardingModule(keycloakClient, keycloakConfig.URIProvider, registerInactiveLockDuration, onboardingRealmOverrides, logger)

		var keycloakComponent management.Component
		{
			// Authorization Checker
			var authorizationChecker management.AuthorizationChecker
			{
				var authorizationLogger = log.With(logger, "svc", "authorization")

				var configurationReaderDBModule *configuration.ConfigurationReaderDBModule
				{
					configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, authorizationLogger, authActions)
				}

				var err error
				authorizationChecker, err = security.NewAuthorizationManager(configurationReaderDBModule, commonKcAdaptor, authorizationLogger)

				if err != nil {
					logger.Error(ctx, "msg", "could not load authorizations", "err", err)
					return
				}
			}
			/* REMOVE_THIS_3901 : remove second parameter */
			keycloakComponent = management.NewComponent(keycloakClient, keycloakConfig.URIProvider, profileCache, auditEventsReporterModule, configDBModule,
				onboardingModule, authorizationChecker, technicalTokenProvider, accreditationsService, trustIDGroups, registerRealm, managementLogger, authReloadProducer)
			keycloakComponent = management.MakeAuthorizationManagementComponentMW(log.With(managementLogger, "mw", "endpoint"), authorizationManager)(keycloakComponent)
		}

		var rateLimitMgmt = rateLimit[RateKeyManagement]
		var rateLimitMgmtStatus = rateLimit[RateKeyManagementStatus]
		managementEndpoints = management.Endpoints{
			GetActions: prepareEndpoint(management.MakeGetActionsEndpoint(keycloakComponent), "get_actions_endpoint", managementLogger, rateLimitMgmt),

			GetRealms: prepareEndpoint(management.MakeGetRealmsEndpoint(keycloakComponent), "realms_endpoint", managementLogger, rateLimitMgmt),
			GetRealm:  prepareEndpoint(management.MakeGetRealmEndpoint(keycloakComponent), "realm_endpoint", managementLogger, rateLimitMgmt),

			GetClients:         prepareEndpoint(management.MakeGetClientsEndpoint(keycloakComponent), "get_clients_endpoint", managementLogger, rateLimitMgmt),
			GetClient:          prepareEndpoint(management.MakeGetClientEndpoint(keycloakComponent), "get_client_endpoint", managementLogger, rateLimitMgmt),
			GetRequiredActions: prepareEndpoint(management.MakeGetRequiredActionsEndpoint(keycloakComponent), "get_required-actions_endpoint", managementLogger, rateLimitMgmt),

			CreateUser:                  prepareEndpoint(management.MakeCreateUserEndpoint(keycloakComponent, profileCache, managementLogger), "create_user_endpoint", managementLogger, rateLimitMgmt),
			CreateUserInSocialRealm:     prepareEndpoint(management.MakeCreateUserInSocialRealmEndpoint(keycloakComponent, profileCache, registerRealm, managementLogger), "create_user_in_social_realm_endpoint", managementLogger, rateLimitMgmt),
			GetUser:                     prepareEndpoint(management.MakeGetUserEndpoint(keycloakComponent), "get_user_endpoint", managementLogger, rateLimitMgmt),
			UpdateUser:                  prepareEndpoint(management.MakeUpdateUserEndpoint(keycloakComponent, profileCache, managementLogger), "update_user_endpoint", managementLogger, rateLimitMgmt),
			LockUser:                    prepareEndpoint(management.MakeLockUserEndpoint(keycloakComponent), "lock_user_endpoint", managementLogger, rateLimitMgmt),
			UnlockUser:                  prepareEndpoint(management.MakeUnlockUserEndpoint(keycloakComponent), "unlock_user_endpoint", managementLogger, rateLimitMgmt),
			DeleteUser:                  prepareEndpoint(management.MakeDeleteUserEndpoint(keycloakComponent), "delete_user_endpoint", managementLogger, rateLimitMgmt),
			GetUsers:                    prepareEndpoint(management.MakeGetUsersEndpoint(keycloakComponent), "get_users_endpoint", managementLogger, rateLimitMgmt),
			GetUserChecks:               prepareEndpoint(management.MakeGetUserChecksEndpoint(keycloakComponent), "get_user_checks", managementLogger, rateLimitMgmt),
			GetUserAccountStatus:        prepareEndpoint(management.MakeGetUserAccountStatusEndpoint(keycloakComponent), "get_user_accountstatus", managementLogger, rateLimitMgmtStatus),
			GetUserAccountStatusByEmail: prepareEndpoint(management.MakeGetUserAccountStatusByEmailEndpoint(keycloakComponent), "get_user_accountstatus_by_email", managementLogger, rateLimitMgmt),
			GetGroupsOfUser:             prepareEndpoint(management.MakeGetGroupsOfUserEndpoint(keycloakComponent), "get_user_groups", managementLogger, rateLimitMgmt),
			AddGroupToUser:              prepareEndpoint(management.MakeAddGroupToUserEndpoint(keycloakComponent), "add_user_group", managementLogger, rateLimitMgmt),
			DeleteGroupForUser:          prepareEndpoint(management.MakeDeleteGroupForUserEndpoint(keycloakComponent), "del_user_group", managementLogger, rateLimitMgmt),
			GetAvailableTrustIDGroups:   prepareEndpoint(management.MakeGetAvailableTrustIDGroupsEndpoint(keycloakComponent), "get_available_trustid_groups_endpoint", managementLogger, rateLimitMgmt),
			GetTrustIDGroupsOfUser:      prepareEndpoint(management.MakeGetTrustIDGroupsOfUserEndpoint(keycloakComponent), "get_user_trustid_groups_endpoint", managementLogger, rateLimitMgmt),
			SetTrustIDGroupsToUser:      prepareEndpoint(management.MakeSetTrustIDGroupsToUserEndpoint(keycloakComponent), "set_user_trustid_groups_endpoint", managementLogger, rateLimitMgmt),
			GetRolesOfUser:              prepareEndpoint(management.MakeGetRolesOfUserEndpoint(keycloakComponent), "get_user_roles", managementLogger, rateLimitMgmt),
			AddRoleToUser:               prepareEndpoint(management.MakeAddRoleToUserEndpoint(keycloakComponent), "add_user_role", managementLogger, rateLimitMgmt),
			DeleteRoleForUser:           prepareEndpoint(management.MakeDeleteRoleForUserEndpoint(keycloakComponent), "delete_user_role", managementLogger, rateLimitMgmt),

			GetRoles:   prepareEndpoint(management.MakeGetRolesEndpoint(keycloakComponent), "get_roles_endpoint", managementLogger, rateLimitMgmt),
			GetRole:    prepareEndpoint(management.MakeGetRoleEndpoint(keycloakComponent), "get_role_endpoint", managementLogger, rateLimitMgmt),
			CreateRole: prepareEndpoint(management.MakeCreateRoleEndpoint(keycloakComponent, managementLogger), "create_role_endpoint", managementLogger, rateLimitMgmt),
			UpdateRole: prepareEndpoint(management.MakeUpdateRoleEndpoint(keycloakComponent), "update_role_endpoint", managementLogger, rateLimitMgmt),
			DeleteRole: prepareEndpoint(management.MakeDeleteRoleEndpoint(keycloakComponent), "delete_role_endpoint", managementLogger, rateLimitMgmt),

			GetGroups:            prepareEndpoint(management.MakeGetGroupsEndpoint(keycloakComponent), "get_groups_endpoint", managementLogger, rateLimitMgmt),
			CreateGroup:          prepareEndpoint(management.MakeCreateGroupEndpoint(keycloakComponent, managementLogger), "create_group_endpoint", managementLogger, rateLimitMgmt),
			DeleteGroup:          prepareEndpoint(management.MakeDeleteGroupEndpoint(keycloakComponent), "delete_group_endpoint", managementLogger, rateLimitMgmt),
			GetAuthorizations:    prepareEndpoint(management.MakeGetAuthorizationsEndpoint(keycloakComponent), "get_authorizations_endpoint", managementLogger, rateLimitMgmt),
			UpdateAuthorizations: prepareEndpoint(management.MakeUpdateAuthorizationsEndpoint(keycloakComponent), "update_authorizations_endpoint", managementLogger, rateLimitMgmt),
			AddAuthorization:     prepareEndpoint(management.MakeAddAuthorizationEndpoint(keycloakComponent), "add_authorization_endpoint", managementLogger, rateLimitMgmt),
			GetAuthorization:     prepareEndpoint(management.MakeGetAuthorizationEndpoint(keycloakComponent), "get_authorization_endpoint", managementLogger, rateLimitMgmt),
			DeleteAuthorization:  prepareEndpoint(management.MakeDeleteAuthorizationEndpoint(keycloakComponent), "delete_authorization_endpoint", managementLogger, rateLimitMgmt),

			GetClientRoles:           prepareEndpoint(management.MakeGetClientRolesEndpoint(keycloakComponent), "get_client_roles_endpoint", managementLogger, rateLimitMgmt),
			CreateClientRole:         prepareEndpoint(management.MakeCreateClientRoleEndpoint(keycloakComponent, managementLogger), "create_client_role_endpoint", managementLogger, rateLimitMgmt),
			DeleteClientRole:         prepareEndpoint(management.MakeDeleteClientRoleEndpoint(keycloakComponent), "delete_client_role_endpoint", managementLogger, rateLimitMgmt),
			GetClientRoleForUser:     prepareEndpoint(management.MakeGetClientRolesForUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", managementLogger, rateLimitMgmt),
			AddClientRoleToUser:      prepareEndpoint(management.MakeAddClientRolesToUserEndpoint(keycloakComponent), "get_client_roles_for_user_endpoint", managementLogger, rateLimitMgmt),
			DeleteClientRoleFromUser: prepareEndpoint(management.MakeDeleteClientRolesFromUserEndpoint(keycloakComponent), "delete_client_roles_from_user_endpoint", managementLogger, rateLimitMgmt),

			ResetPassword:                    prepareEndpointWithoutLogging(management.MakeResetPasswordEndpoint(keycloakComponent), rateLimitMgmt),
			ExecuteActionsEmail:              prepareEndpoint(management.MakeExecuteActionsEmailEndpoint(keycloakComponent), "execute_actions_email_endpoint", managementLogger, rateLimitMgmt),
			RevokeAccreditations:             prepareEndpoint(management.MakeRevokeAccreditationsEndpoint(keycloakComponent), "revoke_accreditations_endpoint", managementLogger, rateLimitMgmt),
			SendOnboardingEmail:              prepareEndpoint(management.MakeSendOnboardingEmailEndpoint(keycloakComponent, maxLifeSpan), "send_onboarding_email_endpoint", managementLogger, rateLimitMgmt),
			SendOnboardingEmailInSocialRealm: prepareEndpoint(management.MakeSendOnboardingEmailInSocialRealmEndpoint(keycloakComponent, maxLifeSpan), "send_onboarding_email_in_social_realm_endpoint", managementLogger, rateLimitMgmt),
			SendReminderEmail:                prepareEndpoint(management.MakeSendReminderEmailEndpoint(keycloakComponent), "send_reminder_email_endpoint", managementLogger, rateLimitMgmt),
			SendSmsCode:                      prepareEndpoint(management.MakeSendSmsCodeEndpoint(keycloakComponent), "send_sms_code_endpoint", managementLogger, rateLimitMgmt),
			ResetSmsCounter:                  prepareEndpoint(management.MakeResetSmsCounterEndpoint(keycloakComponent), "reset_sms_counter_endpoint", managementLogger, rateLimitMgmt),
			CreateRecoveryCode:               prepareEndpoint(management.MakeCreateRecoveryCodeEndpoint(keycloakComponent), "create_recovery_code_endpoint", managementLogger, rateLimitMgmt),
			CreateActivationCode:             prepareEndpoint(management.MakeCreateActivationCodeEndpoint(keycloakComponent), "create_activation_code_endpoint", managementLogger, rateLimitMgmt),
			GetCredentialsForUser:            prepareEndpoint(management.MakeGetCredentialsForUserEndpoint(keycloakComponent), "get_credentials_for_user_endpoint", managementLogger, rateLimitMgmt),
			DeleteCredentialsForUser:         prepareEndpoint(management.MakeDeleteCredentialsForUserEndpoint(keycloakComponent), "delete_credentials_for_user_endpoint", managementLogger, rateLimitMgmt),
			ResetCredentialFailuresForUser:   prepareEndpoint(management.MakeResetCredentialFailuresForUserEndpoint(keycloakComponent), "reset_credential_failures_for_user_endpoint", managementLogger, rateLimitMgmt),
			ClearUserLoginFailures:           prepareEndpoint(management.MakeClearUserLoginFailures(keycloakComponent), "clear_user_login_failures_endpoint", managementLogger, rateLimitMgmt),
			GetAttackDetectionStatus:         prepareEndpoint(management.MakeGetAttackDetectionStatus(keycloakComponent), "get_attack_detection_status_endpoint", managementLogger, rateLimitMgmt),

			/* REMOVE_THIS_3901 : start */
			SendMigrationEmail: prepareEndpoint(management.MakeSendMigrationEmailEndpoint(keycloakComponent, maxLifeSpan), "send_migration_email_endpoint", managementLogger, rateLimitMgmt),
			/* REMOVE_THIS_3901 : end */

			GetRealmCustomConfiguration:    prepareEndpoint(management.MakeGetRealmCustomConfigurationEndpoint(keycloakComponent), "get_realm_custom_config_endpoint", managementLogger, rateLimitMgmt),
			UpdateRealmCustomConfiguration: prepareEndpoint(management.MakeUpdateRealmCustomConfigurationEndpoint(keycloakComponent), "update_realm_custom_config_endpoint", managementLogger, rateLimitMgmt),
			GetRealmAdminConfiguration:     prepareEndpoint(management.MakeGetRealmAdminConfigurationEndpoint(keycloakComponent), "get_realm_admin_config_endpoint", managementLogger, rateLimitMgmt),
			UpdateRealmAdminConfiguration:  prepareEndpoint(management.MakeUpdateRealmAdminConfigurationEndpoint(keycloakComponent), "update_realm_admin_config_endpoint", managementLogger, rateLimitMgmt),
			GetRealmUserProfile:            prepareEndpoint(management.MakeGetRealmUserProfileEndpoint(keycloakComponent), "get_realm_user_profile_endpoint", managementLogger, rateLimitMgmt),

			GetRealmBackOfficeConfiguration:     prepareEndpoint(management.MakeGetRealmBackOfficeConfigurationEndpoint(keycloakComponent), "get_realm_back_office_config_endpoint", managementLogger, rateLimitMgmt),
			UpdateRealmBackOfficeConfiguration:  prepareEndpoint(management.MakeUpdateRealmBackOfficeConfigurationEndpoint(keycloakComponent), "update_realm_back_office_config_endpoint", managementLogger, rateLimitMgmt),
			GetUserRealmBackOfficeConfiguration: prepareEndpoint(management.MakeGetUserRealmBackOfficeConfigurationEndpoint(keycloakComponent), "get_user_realm_back_office_config_endpoint", managementLogger, rateLimitMgmt),
			GetRealmContextKeysConfiguration:    prepareEndpoint(management.MakeGetRealmContextKeysConfigurationEndpoint(keycloakComponent), "get_realm_ctx_keys_config_endpoint", managementLogger, rateLimitMgmt),
			SetRealmContextKeysConfiguration:    prepareEndpoint(management.MakeSetRealmContextKeysConfigurationEndpoint(keycloakComponent), "set_realm_ctx_keys_config_endpoint", managementLogger, rateLimitMgmt),

			GetFederatedIdentities: prepareEndpoint(management.MakeGetFederatedIdentitiesEndpoint(keycloakComponent), "get_federated_identities_endpoint", managementLogger, rateLimitMgmt),
			LinkShadowUser:         prepareEndpoint(management.MakeLinkShadowUserEndpoint(keycloakComponent), "link_shadow_user_endpoint", managementLogger, rateLimitMgmt),
			UnlinkShadowUser:       prepareEndpoint(management.MakeUnlinkShadowUserEndpoint(keycloakComponent), "unlink_shadow_user_endpoint", managementLogger, rateLimitMgmt),
			GetIdentityProviders:   prepareEndpoint(management.MakeGetIdentityProvidersEndpoint(keycloakComponent), "get_identity_providers_endpoint", managementLogger, rateLimitMgmt),

			GetThemeConfiguration:    prepareEndpoint(management.MakeGetThemeConfigurationEndpoint(keycloakComponent), "get_theme_configuration_endpoint", managementLogger, rateLimitMgmt),
			UpdateThemeConfiguration: prepareEndpoint(management.MakeUpdateThemeConfigurationEndpoint(keycloakComponent), "update_theme_configuration_endpoint", managementLogger, rateLimitMgmt),
			GetThemeTranslation:      prepareEndpoint(management.MakeGetThemeTranslationEndpoint(keycloakComponent), "get_theme_translations_endpoint", managementLogger, rateLimitMgmt),
		}
	}

	// Account service.
	var accountEndpoints account.Endpoints
	{
		var accountLogger = log.With(logger, "svc", "account")

		// Configure events db module
		auditEventsReporterModule := csevents.NewAuditEventReporterModule(eventProducer, accountLogger)

		// module for retrieving the custom configuration
		var configDBModule = keycloakb.NewConfigurationDBModule(configurationRoDBConn, accountLogger)

		var kcTechClient keycloakb.KeycloakTechnicalClient
		{
			kcTechClient = keycloakb.NewKeycloakTechnicalClient(technicalTokenProvider, technicalRealm, keycloakClient, accountLogger)
		}

		var logAuthorization = log.With(accountLogger, "mw", "authorization")
		var logEndpoint = log.With(accountLogger, "mw", "endpoint")

		// new module for account service
		accountComponent := account.NewComponent(keycloakClient.AccountClient(), kcTechClient, profileCache, auditEventsReporterModule, configDBModule, accreditationsService, accountLogger)
		accountComponent = account.MakeAuthorizationAccountComponentMW(logAuthorization, configDBModule)(accountComponent)

		var rateLimitAccount = rateLimit[RateKeyAccount]
		accountEndpoints = account.Endpoints{
			GetAccount:                prepareEndpoint(account.MakeGetAccountEndpoint(accountComponent), "get_account", accountLogger, rateLimitAccount),
			UpdateAccount:             prepareEndpoint(account.MakeUpdateAccountEndpoint(accountComponent, profileCache, logEndpoint), "update_account", accountLogger, rateLimitAccount),
			DeleteAccount:             prepareEndpoint(account.MakeDeleteAccountEndpoint(accountComponent), "delete_account", accountLogger, rateLimitAccount),
			UpdatePassword:            prepareEndpointWithoutLogging(account.MakeUpdatePasswordEndpoint(accountComponent), rateLimitAccount),
			GetCredentials:            prepareEndpoint(account.MakeGetCredentialsEndpoint(accountComponent), "get_credentials", accountLogger, rateLimitAccount),
			GetCredentialRegistrators: prepareEndpoint(account.MakeGetCredentialRegistratorsEndpoint(accountComponent), "get_credential_registrators", accountLogger, rateLimitAccount),
			DeleteCredential:          prepareEndpoint(account.MakeDeleteCredentialEndpoint(accountComponent), "delete_credential", accountLogger, rateLimitAccount),
			UpdateLabelCredential:     prepareEndpoint(account.MakeUpdateLabelCredentialEndpoint(accountComponent), "update_label_credential", accountLogger, rateLimitAccount),
			MoveCredential:            prepareEndpoint(account.MakeMoveCredentialEndpoint(accountComponent), "move_credential", accountLogger, rateLimitAccount),
			GetConfiguration:          prepareEndpoint(account.MakeGetConfigurationEndpoint(accountComponent), "get_configuration", accountLogger, rateLimitAccount),
			GetProfile:                prepareEndpoint(account.MakeGetUserProfileEndpoint(accountComponent), "get_profile", accountLogger, rateLimitAccount),
			SendVerifyEmail:           prepareEndpoint(account.MakeSendVerifyEmailEndpoint(accountComponent), "send_verify_email", accountLogger, rateLimitAccount),
			SendVerifyPhoneNumber:     prepareEndpoint(account.MakeSendVerifyPhoneNumberEndpoint(accountComponent), "send_verify_phone_number", accountLogger, rateLimitAccount),
			CancelEmailChange:         prepareEndpoint(account.MakeCancelEmailChangeEndpoint(accountComponent), "cancel_email_change", accountLogger, rateLimitAccount),
			CancelPhoneNumberChange:   prepareEndpoint(account.MakeCancelPhoneNumberChangeEndpoint(accountComponent), "cancel_phone_number_change", accountLogger, rateLimitAccount),
			GetLinkedAccounts:         prepareEndpoint(account.MakeGetLinkedAccountsEndpoint(accountComponent), "get_linked_accounts", accountLogger, rateLimitAccount),
			DeleteLinkedAccount:       prepareEndpoint(account.MakeDeleteLinkedAccountEndpoint(accountComponent), "delete_linked_account", accountLogger, rateLimitAccount),
		}
	}

	// Mobile service.
	var mobileEndpoints mobile.Endpoints
	{
		var mobileLogger = log.With(logger, "svc", "mobile")

		// module for retrieving the custom configuration
		var configDBModule = keycloakb.NewConfigurationDBModule(configurationRoDBConn, mobileLogger)

		var httpClient, err = httpclient.NewBearerAuthClient(c.GetString(cfgAddrAccounting), c.GetDuration(cfgAccountingTimeout), func() (string, error) {
			return technicalTokenProvider.ProvideTokenForRealm(context.TODO(), "master")
		})
		if err != nil {
			logger.Error(ctx, "msg", "could not initialize accounting client", "err", err)
			return
		}

		var accountingClient = keycloakb.MakeAccountingClient(httpClient)

		// new module for mobile service
		mobileComponent := mobile.NewComponent(keycloakClient, configDBModule, accreditationsService, technicalTokenProvider, authorizationManager, roleBasedAuthorizationManager, accountingClient, mobileLogger)
		mobileComponent = mobile.MakeAuthorizationMobileComponentMW(log.With(mobileLogger, "mw", "authorization"))(mobileComponent)

		var rateLimitMobile = rateLimit[RateKeyMobile]
		mobileEndpoints = mobile.Endpoints{
			GetUserInformation: prepareEndpoint(mobile.MakeGetUserInformationEndpoint(mobileComponent), "get_user_information", mobileLogger, rateLimitMobile),
		}
	}

	// Register service.
	var registerEndpoints register.Endpoints
	{
		var registerLogger = log.With(logger, "svc", "register")

		// Configure events db module
		auditEventsReporterModule := csevents.NewAuditEventReporterModule(eventProducer, registerLogger)

		// module for storing and retrieving the custom configuration
		var configDBModule = createConfigurationDBModule(configurationRwDBConn, registerLogger)
		var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, registerLogger, authActions)

		// module for onboarding process
		var onboardingModule = keycloakb.NewOnboardingModule(keycloakClient, keycloakConfig.URIProvider, registerInactiveLockDuration, onboardingRealmOverrides, registerLogger)

		// context keys
		contextKeyManager := keycloakb.MakeContextKeyManager(configurationReaderDBModule)

		registerComponent := register.NewComponent(keycloakClient, technicalTokenProvider, profileCache, configDBModule, auditEventsReporterModule, onboardingModule, contextKeyManager, registerLogger)
		registerComponent = register.MakeAuthorizationRegisterComponentMW(log.With(registerLogger, "mw", "authorization"))(registerComponent)

		var rateLimitRegister = rateLimit[RateKeyRegister]
		registerEndpoints = register.Endpoints{
			RegisterUser:       prepareEndpoint(register.MakeRegisterUserEndpoint(registerComponent, registerRealm, profileCache, registerLogger), "register_user", registerLogger, rateLimitRegister),
			RegisterCorpUser:   prepareEndpoint(register.MakeRegisterCorpUserEndpoint(registerComponent, profileCache, registerLogger), "register_corp_user", registerLogger, rateLimitRegister),
			GetConfiguration:   prepareEndpoint(register.MakeGetConfigurationEndpoint(registerComponent), "get_configuration", registerLogger, rateLimitRegister),
			GetUserProfile:     prepareEndpoint(register.MakeGetUserProfileEndpoint(registerComponent, registerRealm), "get_user_profile", registerLogger, rateLimitRegister),
			GetCorpUserProfile: prepareEndpoint(register.MakeGetCorpUserProfileEndpoint(registerComponent), "get_corp_user_profile", registerLogger, rateLimitRegister),
		}
	}

	// Configuration service.
	var configurationEndpoints conf.Endpoints
	{
		configurationLogger := log.With(logger, "svc", "configuration")

		// context keys
		var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, configurationLogger, authActions)
		contextKeyManager := keycloakb.MakeContextKeyManager(configurationReaderDBModule)

		configurationComponent := conf.NewComponent(contextKeyManager, configurationLogger)

		rateLimitRegister := rateLimit[RateKeyRegister]
		configurationEndpoints = conf.Endpoints{
			GetIdentificationURI: prepareEndpoint(conf.MakeGetIdentificationURIEndpoint(configurationComponent), "get_identification_uri", configurationLogger, rateLimitRegister),
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
		auditEventsReporterModule := csevents.NewAuditEventReporterModule(eventProducer, kycLogger)

		// module for archiving users
		var archiveDBModule = keycloakb.NewArchiveDBModule(archiveRwDBConn, archiveAesEncryption, kycLogger)

		// config
		var configurationReaderDBModule = configuration.NewConfigurationReaderDBModule(configurationRoDBConn, kycLogger)

		// new module for KYC service
		kycComponent := kyc.NewComponent(technicalTokenProvider, registerRealm, keycloakClient, profileCache, archiveDBModule, configurationReaderDBModule, auditEventsReporterModule, accreditationsService, kycLogger)
		kycComponent = kyc.MakeAuthorizationKYCComponentMW(registerRealm, authorizationManager, roleBasedAuthorizationManager, endpointPhysicalCheckAvailabilityChecker, log.With(kycLogger, "mw", "authorization"))(kycComponent)

		var rateLimitKyc = rateLimit[RateKeyKYC]
		kycEndpoints = kyc.Endpoints{
			GetActions:                      prepareEndpoint(kyc.MakeGetActionsEndpoint(kycComponent), "register_get_actions", kycLogger, rateLimitKyc),
			GetUserInSocialRealm:            prepareEndpoint(kyc.MakeGetUserInSocialRealmEndpoint(kycComponent), "get_user_in_social_realm", kycLogger, rateLimitKyc),
			GetUserProfileInSocialRealm:     prepareEndpoint(kyc.MakeGetUserProfileInSocialRealmEndpoint(kycComponent), "get_user_profile_in_social_realm", kycLogger, rateLimitKyc),
			GetUserByUsernameInSocialRealm:  prepareEndpoint(kyc.MakeGetUserByUsernameInSocialRealmEndpoint(kycComponent), "get_user_by_username_in_social_realm", kycLogger, rateLimitKyc),
			ValidateUserInSocialRealm:       prepareEndpoint(kyc.MakeValidateUserInSocialRealmEndpoint(kycComponent, profileCache, registerRealm, kycLogger), "validate_user_in_social_realm", kycLogger, rateLimitKyc),
			SendSMSConsentCodeInSocialRealm: prepareEndpoint(kyc.MakeSendSmsConsentCodeInSocialRealmEndpoint(kycComponent), "send_sms_consent_code_in_social_realm", kycLogger, rateLimitKyc),
			SendSMSCodeInSocialRealm:        prepareEndpoint(kyc.MakeSendSmsCodeInSocialRealmEndpoint(kycComponent), "send_sms_code_in_social_realm", kycLogger, rateLimitKyc),
			GetUser:                         prepareEndpoint(kyc.MakeGetUserEndpoint(kycComponent), "get_user", kycLogger, rateLimitKyc),
			GetUserProfile:                  prepareEndpoint(kyc.MakeGetUserProfileEndpoint(kycComponent), "get_user_profile", kycLogger, rateLimitKyc),
			GetUserByUsername:               prepareEndpoint(kyc.MakeGetUserByUsernameEndpoint(kycComponent), "get_user_by_username", kycLogger, rateLimitKyc),
			ValidateUser:                    prepareEndpoint(kyc.MakeValidateUserEndpoint(kycComponent, profileCache, kycLogger), "validate_user", kycLogger, rateLimitKyc),
			SendSMSConsentCode:              prepareEndpoint(kyc.MakeSendSmsConsentCodeEndpoint(kycComponent), "send_sms_consent_code", kycLogger, rateLimitKyc),
			SendSMSCode:                     prepareEndpoint(kyc.MakeSendSmsCodeEndpoint(kycComponent), "send_sms_code", kycLogger, rateLimitKyc),

			ValidateUserBasic: prepareEndpoint(kyc.MakeValidateUserBasicIDEndpoint(kycComponent, profileCache, registerRealm, kycLogger), "basic_validate_user", kycLogger, rateLimitKyc), /***TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED***/
		}
	}

	// Identity providers service.
	var idpEndpoints idp.Endpoints
	{
		var idpLogger = log.With(logger, "svc", "identity-providers")

		// HRD configuration
		var hrdConfig toolbox.ComponentConfig
		{
			if err := c.UnmarshalKey(cfgHrd, &hrdConfig); err != nil {
				logger.Error(ctx, "msg", "Can't get HRD component tool configuration for "+cfgHrd)
			}
		}

		// HRD component tool
		var hrdTool toolbox.ComponentTool
		{
			hrdTool = toolbox.NewComponentTool(hrdConfig)
		}

		idpComponent := idp.NewComponent(keycloakClient, technicalTokenProvider, hrdTool, idpLogger)
		idpEndpoints = idp.NewEndpoints(idpComponent, func(endpoint cs.Endpoint, name string) endpoint.Endpoint {
			return prepareEndpoint(endpoint, name, idpLogger, rateLimit[RateKeyIDP])
		})
	}

	// HTTP Monitoring (For monitoring probes, ...).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrMonitoring)

		var route = mux.NewRouter()
		var limiter = rate.NewLimiter(rate.Every(time.Second), rateLimit[RateKeyMonitoring])

		route.Handle("/", commonhttp.MakeVersionHandler(keycloakb.ComponentName, ComponentID, keycloakb.Version, Environment, GitCommit))
		route.Handle(pathHealthCheck, healthChecker.MakeHandler(limiter))
		route.Handle(pathHealthLive, livenessChecker.MakeHandler(limiter))

		errc <- http.ListenAndServe(httpAddrMonitoring, route)
	}()

	// HTTP Internal Call Server (Communications, Support, Tasks, Validation & IDP API).
	go func() {
		var logger = log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrInternal, "interface", "export-and-communication")

		var route = mux.NewRouter()

		// Validation (basic auth)
		var getUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, logger)(validationEndpoints.GetUser)
		var updateUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, logger)(validationEndpoints.UpdateUser)
		var updateUserAccreditationsHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, logger)(validationEndpoints.UpdateUserAccreditations)
		var getGroupsForUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, logger)(validationEndpoints.GetGroupsOfUser)
		var getRolesForUserHandler = configureValidationHandler(keycloakb.ComponentName, ComponentID, idGenerator, validationExpectedAuthToken, logger)(validationEndpoints.GetRolesOfUser)

		var validationSubroute = route.PathPrefix("/validation").Subrouter()

		validationSubroute.Path("/realms/{realm}/users/{userID}").Methods("GET").Handler(getUserHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}").Methods("PUT").Handler(updateUserHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}/accreditations").Methods("PUT").Handler(updateUserAccreditationsHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}/groups").Methods("GET").Handler(getGroupsForUserHandler)
		validationSubroute.Path("/realms/{realm}/users/{userID}/roles").Methods("GET").Handler(getRolesForUserHandler)

		// Communications (bearer auth)
		var sendMailHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, communications.MakeCommunicationsHandler, logger)(communicationsEndpoints.SendEmail)
		var sendMailToUserHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, communications.MakeCommunicationsHandler, logger)(communicationsEndpoints.SendEmailToUser)
		var sendSMSHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, communications.MakeCommunicationsHandler, logger)(communicationsEndpoints.SendSMS)

		var communicationsSubroute = route.PathPrefix("/communications").Subrouter()

		communicationsSubroute.Path("/realms/{realm}/send-mail").Methods("POST").Handler(sendMailHandler)
		communicationsSubroute.Path("/realms/{realm}/users/{userID}/send-email").Methods("POST").Handler(sendMailToUserHandler)
		communicationsSubroute.Path("/realms/{realm}/send-sms").Methods("POST").Handler(sendSMSHandler)

		// Support (bearer auth)
		var getSupportInfosHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, support.MakeSupportHandler, logger)(supportEndpoints.GetSupportInformation)

		route.PathPrefix("/support/accounts").Methods("GET").Handler(getSupportInfosHandler)

		// Tasks (bearer auth)
		var deniedToUUsersHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, tasks.MakeTasksHandler, logger)(tasksEndpoints.DeleteDeniedToUUsers)

		route.PathPrefix("/tasks/denied-terms-of-use-users").Methods("DELETE").Handler(deniedToUUsersHandler)

		var configureIDPHandler = func(endpoint endpoint.Endpoint) http.Handler {
			return configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, idp.MakeIdpHandler, logger)(endpoint)
		}

		// Identity providers (bearer auth)
		var getIdentityProviderHandler = configureIDPHandler(idpEndpoints.GetIdentityProvider)
		var createIdentityProviderHandler = configureIDPHandler(idpEndpoints.CreateIdentityProvider)
		var updateIdentityProviderHandler = configureIDPHandler(idpEndpoints.UpdateIdentityProvider)
		var deleteIdentityProviderHandler = configureIDPHandler(idpEndpoints.DeleteIdentityProvider)
		var getIdentityProviderMappersHandler = configureIDPHandler(idpEndpoints.GetIdentityProviderMappers)
		var createIdentityProviderMapperHandler = configureIDPHandler(idpEndpoints.CreateIdentityProviderMapper)
		var updateIdentityProviderMapperHandler = configureIDPHandler(idpEndpoints.UpdateIdentityProviderMapper)
		var deleteIdentityProviderMapperHandler = configureIDPHandler(idpEndpoints.DeleteIdentityProviderMapper)
		var getIDPUsersWithAttributeHandler = configureIDPHandler(idpEndpoints.GetUsersWithAttribute)
		var deleteIDPUserHandler = configureIDPHandler(idpEndpoints.DeleteUser)
		var addIDPUserAttributesHandler = configureIDPHandler(idpEndpoints.AddUserAttributes)
		var deleteIDPUserAttributesHandler = configureIDPHandler(idpEndpoints.DeleteUserAttributes)
		var getUserFederatedIdentitiesHandler = configureIDPHandler(idpEndpoints.GetUserFederatedIdentities)

		var idpSubroute = route.PathPrefix("/idp").Subrouter()

		idpSubroute.Path("/realms/{realm}/identity-providers").Methods("POST").Handler(createIdentityProviderHandler)
		idpSubroute.Path("/realms/{realm}/identity-providers/{provider}").Methods("GET").Handler(getIdentityProviderHandler)
		idpSubroute.Path("/realms/{realm}/identity-providers/{provider}").Methods("PUT").Handler(updateIdentityProviderHandler)
		idpSubroute.Path("/realms/{realm}/identity-providers/{provider}").Methods("DELETE").Handler(deleteIdentityProviderHandler)
		idpSubroute.Path("/realms/{realm}/identity-providers/{provider}/mappers").Methods("GET").Handler(getIdentityProviderMappersHandler)
		idpSubroute.Path("/realms/{realm}/identity-providers/{provider}/mappers").Methods("POST").Handler(createIdentityProviderMapperHandler)
		idpSubroute.Path("/realms/{realm}/identity-providers/{provider}/mappers/{mapper}").Methods("PUT").Handler(updateIdentityProviderMapperHandler)
		idpSubroute.Path("/realms/{realm}/identity-providers/{provider}/mappers/{mapper}").Methods("DELETE").Handler(deleteIdentityProviderMapperHandler)
		idpSubroute.Path("/realms/{realm}/users").Methods("GET").Handler(getIDPUsersWithAttributeHandler)
		idpSubroute.Path("/realms/{realm}/users/{user}").Methods("DELETE").Handler(deleteIDPUserHandler)
		idpSubroute.Path("/realms/{realm}/users/{user}/attributes").Methods("PUT").Handler(addIDPUserAttributesHandler)
		idpSubroute.Path("/realms/{realm}/users/{user}/attributes").Methods("DELETE").Handler(deleteIDPUserAttributesHandler)
		idpSubroute.Path("/realms/{realm}/users/{user}/federated-identities").Methods("GET").Handler(getUserFederatedIdentitiesHandler)

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
		logger.Info(ctx, "addr", httpAddrManagement, "interface", "management")

		var route = mux.NewRouter()

		// Rights
		var rightsHandler = configureRightsHandler(keycloakb.ComponentName, ComponentID, idGenerator, authorizationManager, keycloakClient, audienceRequired, logger)
		route.Path("/rights").Methods("GET").Handler(rightsHandler)

		// Statistics
		var configureStatisticsHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, statistics.MakeStatisticsHandler, logger)

		var getStatisticsActionsHandler = configureStatisticsHandler(statisticsEndpoints.GetActions)
		var getStatisticsIdentificationsHandler = configureStatisticsHandler(statisticsEndpoints.GetStatisticsIdentifications)
		var getStatisticsUsersHandler = configureStatisticsHandler(statisticsEndpoints.GetStatisticsUsers)
		var getStatisticsAuthenticatorsHandler = configureStatisticsHandler(statisticsEndpoints.GetStatisticsAuthenticators)
		var getMigrationReportHandler = configureStatisticsHandler(statisticsEndpoints.GetMigrationReport)

		route.Path("/statistics/actions").Methods("GET").Handler(getStatisticsActionsHandler)
		route.Path("/statistics/realms/{realm}/identifications").Methods("GET").Handler(getStatisticsIdentificationsHandler)
		route.Path("/statistics/realms/{realm}/users").Methods("GET").Handler(getStatisticsUsersHandler)
		route.Path("/statistics/realms/{realm}/authenticators").Methods("GET").Handler(getStatisticsAuthenticatorsHandler)
		route.Path("/statistics/realms/{realm}/migration").Methods("GET").Handler(getMigrationReportHandler)

		// Management
		var managementSubroute = route.PathPrefix("/management").Subrouter()

		var configureManagementHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, management.MakeManagementHandler, logger)

		var getRealmsHandler = configureManagementHandler(managementEndpoints.GetRealms)
		var getRealmHandler = configureManagementHandler(managementEndpoints.GetRealm)

		var getClientsHandler = configureManagementHandler(managementEndpoints.GetClients)
		var getClientHandler = configureManagementHandler(managementEndpoints.GetClient)

		var getRequiredActionsHandler = configureManagementHandler(managementEndpoints.GetRequiredActions)

		var createUserHandler = configureManagementHandler(managementEndpoints.CreateUser)
		var createUserInSocialRealmHandler = configureManagementHandler(managementEndpoints.CreateUserInSocialRealm)
		var getUserHandler = configureManagementHandler(managementEndpoints.GetUser)
		var updateUserHandler = configureManagementHandler(managementEndpoints.UpdateUser)
		var lockUserHandler = configureManagementHandler(managementEndpoints.LockUser)
		var unlockUserHandler = configureManagementHandler(managementEndpoints.UnlockUser)
		var deleteUserHandler = configureManagementHandler(managementEndpoints.DeleteUser)
		var getUsersHandler = configureManagementHandler(managementEndpoints.GetUsers)
		var getRolesForUserHandler = configureManagementHandler(managementEndpoints.GetRolesOfUser)
		var addRoleToUser = configureManagementHandler(managementEndpoints.AddRoleToUser)
		var deleteRoleForUser = configureManagementHandler(managementEndpoints.DeleteRoleForUser)
		var getGroupsForUserHandler = configureManagementHandler(managementEndpoints.GetGroupsOfUser)
		var addGroupToUserHandler = configureManagementHandler(managementEndpoints.AddGroupToUser)
		var deleteGroupForUserHandler = configureManagementHandler(managementEndpoints.DeleteGroupForUser)
		var getUserChecksHandler = configureManagementHandler(managementEndpoints.GetUserChecks)
		var getUserAccountStatusHandler = configureManagementHandler(managementEndpoints.GetUserAccountStatus)
		var getUserAccountStatusByEmailHandler = configureManagementHandler(managementEndpoints.GetUserAccountStatusByEmail)
		var getAvailableTrustIDGroupsHandler = configureManagementHandler(managementEndpoints.GetAvailableTrustIDGroups)
		var getTrustIDGroupsOfUserHandler = configureManagementHandler(managementEndpoints.GetTrustIDGroupsOfUser)
		var setTrustIDGroupsToUserHandler = configureManagementHandler(managementEndpoints.SetTrustIDGroupsToUser)

		var getClientRoleForUserHandler = configureManagementHandler(managementEndpoints.GetClientRoleForUser)
		var addClientRoleToUserHandler = configureManagementHandler(managementEndpoints.AddClientRoleToUser)
		var deleteClientRoleFromUserHandler = configureManagementHandler(managementEndpoints.DeleteClientRoleFromUser)

		var getRolesHandler = configureManagementHandler(managementEndpoints.GetRoles)
		var getRoleHandler = configureManagementHandler(managementEndpoints.GetRole)
		var createRoleHandler = configureManagementHandler(managementEndpoints.CreateRole)
		var updateRoleHandler = configureManagementHandler(managementEndpoints.UpdateRole)
		var deleteRoleHandler = configureManagementHandler(managementEndpoints.DeleteRole)
		var getClientRolesHandler = configureManagementHandler(managementEndpoints.GetClientRoles)
		var createClientRolesHandler = configureManagementHandler(managementEndpoints.CreateClientRole)
		var deleteClientRolesHandler = configureManagementHandler(managementEndpoints.DeleteClientRole)

		var getGroupsHandler = configureManagementHandler(managementEndpoints.GetGroups)
		var createGroupHandler = configureManagementHandler(managementEndpoints.CreateGroup)
		var deleteGroupHandler = configureManagementHandler(managementEndpoints.DeleteGroup)
		var getAuthorizationsHandler = configureManagementHandler(managementEndpoints.GetAuthorizations)
		var updateAuthorizationsHandler = configureManagementHandler(managementEndpoints.UpdateAuthorizations)
		var addAuthorizationHandler = configureManagementHandler(managementEndpoints.AddAuthorization)
		var getAuthorizationHandler = configureManagementHandler(managementEndpoints.GetAuthorization)
		var deleteAuthorizationHandler = configureManagementHandler(managementEndpoints.DeleteAuthorization)
		var getManagementActionsHandler = configureManagementHandler(managementEndpoints.GetActions)

		var resetPasswordHandler = configureManagementHandler(managementEndpoints.ResetPassword)
		var executeActionsEmailHandler = configureManagementHandler(managementEndpoints.ExecuteActionsEmail)
		var revokeAccreditationsHandler = configureManagementHandler(managementEndpoints.RevokeAccreditations)
		var sendSmsCodeHandler = configureManagementHandler(managementEndpoints.SendSmsCode)
		var sendOnboardingEmailHandler = configureManagementHandler(managementEndpoints.SendOnboardingEmail)
		var sendOnboardingEmailInSocialRealmHandler = configureManagementHandler(managementEndpoints.SendOnboardingEmailInSocialRealm)
		var sendReminderEmailHandler = configureManagementHandler(managementEndpoints.SendReminderEmail)
		var resetSmsCounterHandler = configureManagementHandler(managementEndpoints.ResetSmsCounter)
		var createRecoveryCodeHandler = configureManagementHandler(managementEndpoints.CreateRecoveryCode)
		var createActivationCodeHandler = configureManagementHandler(managementEndpoints.CreateActivationCode)

		/* REMOVE_THIS_3901 : start */
		var sendMigrationEmail = configureManagementHandler(managementEndpoints.SendMigrationEmail)
		/* REMOVE_THIS_3901 : end */

		var getCredentialsForUserHandler = configureManagementHandler(managementEndpoints.GetCredentialsForUser)
		var deleteCredentialsForUserHandler = configureManagementHandler(managementEndpoints.DeleteCredentialsForUser)
		var resetCredentialFailuresForUserHandler = configureManagementHandler(managementEndpoints.ResetCredentialFailuresForUser)
		var clearUserLoginFailuresHandler = configureManagementHandler(managementEndpoints.ClearUserLoginFailures)
		var getAttackDetectionStatusHandler = configureManagementHandler(managementEndpoints.GetAttackDetectionStatus)

		var getRealmCustomConfigurationHandler = configureManagementHandler(managementEndpoints.GetRealmCustomConfiguration)
		var updateRealmCustomConfigurationHandler = configureManagementHandler(managementEndpoints.UpdateRealmCustomConfiguration)
		var getRealmAdminConfigurationHandler = configureManagementHandler(managementEndpoints.GetRealmAdminConfiguration)
		var updateRealmAdminConfigurationHandler = configureManagementHandler(managementEndpoints.UpdateRealmAdminConfiguration)

		var getRealmUserProfileHandler = configureManagementHandler(managementEndpoints.GetRealmUserProfile)

		var getRealmBackOfficeConfigurationHandler = configureManagementHandler(managementEndpoints.GetRealmBackOfficeConfiguration)
		var updateRealmBackOfficeConfigurationHandler = configureManagementHandler(managementEndpoints.UpdateRealmBackOfficeConfiguration)
		var getUserRealmBackOfficeConfigurationHandler = configureManagementHandler(managementEndpoints.GetUserRealmBackOfficeConfiguration)
		var getRealmContextKeysConfigurationHandler = configureManagementHandler(managementEndpoints.GetRealmContextKeysConfiguration)
		var setRealmContextKeysConfigurationHandler = configureManagementHandler(managementEndpoints.SetRealmContextKeysConfiguration)

		var getFederatedIdentitiesHandler = configureManagementHandler(managementEndpoints.GetFederatedIdentities)
		var linkShadowUserHandler = configureManagementHandler(managementEndpoints.LinkShadowUser)
		var unlinkShadowUserHandler = configureManagementHandler(managementEndpoints.UnlinkShadowUser)

		var getIdentityProvidersHandler = configureManagementHandler(managementEndpoints.GetIdentityProviders)

		var getThemeConfigurationHandler = configureManagementHandler(managementEndpoints.GetThemeConfiguration)
		var updateThemeConfigurationHandler = configureManagementHandler(managementEndpoints.UpdateThemeConfiguration)
		var getThemeTranslationHandler = configureManagementHandler(managementEndpoints.GetThemeTranslation)

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
		managementSubroute.Path("/realms/{realm}/users/profile").Methods("GET").Handler(getRealmUserProfileHandler)
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
		managementSubroute.Path("/social/users").Methods("POST").Handler(createUserInSocialRealmHandler)

		// role mappings
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("GET").Handler(getClientRoleForUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}").Methods("POST").Handler(addClientRoleToUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/role-mappings/clients/{clientID}/roles/{roleID}").Methods("DELETE").Handler(deleteClientRoleFromUserHandler)

		managementSubroute.Path("/realms/{realm}/users/{userID}/reset-password").Methods("PUT").Handler(resetPasswordHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/execute-actions-email").Methods("PUT").Handler(executeActionsEmailHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-sms-code").Methods("POST").Handler(sendSmsCodeHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-onboarding-email").Methods("POST").Handler(sendOnboardingEmailHandler)
		managementSubroute.Path("/social/users/{userID}/send-onboarding-email").Methods("POST").Handler(sendOnboardingEmailInSocialRealmHandler)
		/* REMOVE_THIS_3901 : start */
		managementSubroute.Path("/realms/{realm}/users/{userID}/send-migration-email").Methods("POST").Handler(sendMigrationEmail)
		/* REMOVE_THIS_3901 : end */
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
		managementSubroute.Path("/realms/{realm}/roles").Methods("POST").Handler(createRoleHandler)
		managementSubroute.Path("/realms/{realm}/roles/{roleID}").Methods("GET").Handler(getRoleHandler)
		managementSubroute.Path("/realms/{realm}/roles/{roleID}").Methods("PUT").Handler(updateRoleHandler)
		managementSubroute.Path("/realms/{realm}/roles/{roleID}").Methods("DELETE").Handler(deleteRoleHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}/roles").Methods("GET").Handler(getClientRolesHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}/roles").Methods("POST").Handler(createClientRolesHandler)
		managementSubroute.Path("/realms/{realm}/clients/{clientID}/roles/{roleID}").Methods("DELETE").Handler(deleteClientRolesHandler)

		// groups
		managementSubroute.Path("/realms/{realm}/groups").Methods("GET").Handler(getGroupsHandler)
		managementSubroute.Path("/realms/{realm}/groups").Methods("POST").Handler(createGroupHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}").Methods("DELETE").Handler(deleteGroupHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}/authorizations").Methods("GET").Handler(getAuthorizationsHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}/authorizations").Methods("PUT").Handler(updateAuthorizationsHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}/actions/{action}/authorizations").Methods("PUT").Handler(addAuthorizationHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}/actions/{action}/authorizations").Methods("GET").Handler(getAuthorizationHandler)
		managementSubroute.Path("/realms/{realm}/groups/{groupID}/actions/{action}/authorizations").Methods("DELETE").Handler(deleteAuthorizationHandler)

		// custom configuration per realm
		managementSubroute.Path("/realms/{realm}/configuration").Methods("GET").Handler(getRealmCustomConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/configuration").Methods("PUT").Handler(updateRealmCustomConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/admin-configuration").Methods("GET").Handler(getRealmAdminConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/admin-configuration").Methods("PUT").Handler(updateRealmAdminConfigurationHandler)

		managementSubroute.Path("/realms/{realm}/backoffice-configuration/groups").Methods("GET").Handler(getRealmBackOfficeConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/backoffice-configuration/groups").Methods("PUT").Handler(updateRealmBackOfficeConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/backoffice-configuration").Methods("GET").Handler(getUserRealmBackOfficeConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/context-keys").Methods("GET").Handler(getRealmContextKeysConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/context-keys").Methods("POST").Handler(setRealmContextKeysConfigurationHandler)

		// brokering - shadow users
		managementSubroute.Path("/realms/{realm}/users/{userID}/federated-identity").Methods("GET").Handler(getFederatedIdentitiesHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/federated-identity/{provider}").Methods("POST").Handler(linkShadowUserHandler)
		managementSubroute.Path("/realms/{realm}/users/{userID}/federated-identity/{provider}").Methods("DELETE").Handler(unlinkShadowUserHandler)

		managementSubroute.Path("/realms/{realm}/identity-providers").Methods("GET").Handler(getIdentityProvidersHandler)

		managementSubroute.Path("/realms/{realm}/theme-configuration").Methods("GET").Handler(getThemeConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/theme-configuration").Methods("PUT").Handler(updateThemeConfigurationHandler)
		managementSubroute.Path("/realms/{realm}/theme-translation/{language}").Methods("GET").Handler(getThemeTranslationHandler)

		// Accreditations
		route.Path("/accreditations/realms/{realm}/users/{userID}/revoke-accreditations").Methods("PUT").Handler(revokeAccreditationsHandler)

		// KYC handlers
		var kycGetActionsHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.GetActions)
		var kycGetUserInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUserInSocialRealm)
		var kycGetUserProfileInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.GetUserProfileInSocialRealm)
		var kycGetUserByUsernameInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUserByUsernameInSocialRealm)
		var kycValidateUserInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.ValidateUserInSocialRealm)
		var kycSendSMSConsentCodeInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSConsentCodeInSocialRealm)
		var kycSendSMSCodeInSocialRealmHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSCodeInSocialRealm)
		var kycGetUserHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUser)
		var kycGetUserProfileHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.GetUserProfile)
		var kycGetUserByUsernameHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, true, logger)(kycEndpoints.GetUserByUsername)
		var kycValidateUserHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.ValidateUser)
		var kycSendSMSConsentCodeHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSConsentCode)
		var kycSendSMSCodeHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.SendSMSCode)

		// KYC methods
		route.Path("/kyc/actions").Methods("GET").Handler(kycGetActionsHandler)
		route.Path("/kyc/social/users").Methods("GET").Handler(kycGetUserByUsernameInSocialRealmHandler)
		route.Path("/kyc/social/users/profile").Methods("GET").Handler(kycGetUserProfileInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}").Methods("GET").Handler(kycGetUserInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}").Methods("PUT").Handler(kycValidateUserInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}/send-consent-code").Methods("POST").Handler(kycSendSMSConsentCodeInSocialRealmHandler)
		route.Path("/kyc/social/users/{userID}/send-sms-code").Methods("POST").Handler(kycSendSMSCodeInSocialRealmHandler)
		route.Path("/kyc/realms/{realm}/users").Methods("GET").Handler(kycGetUserByUsernameHandler)
		route.Path("/kyc/realms/{realm}/users/profile").Methods("GET").Handler(kycGetUserProfileHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}").Methods("GET").Handler(kycGetUserHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}").Methods("PUT").Handler(kycValidateUserHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}/send-consent-code").Methods("POST").Handler(kycSendSMSConsentCodeHandler)
		route.Path("/kyc/realms/{realm}/users/{userID}/send-sms-code").Methods("POST").Handler(kycSendSMSCodeHandler)

		/********************* (BEGIN) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/
		var kycValidateUserBasicIDHandler = configureKYCHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, endpointPhysicalCheckAvailabilityChecker, false, logger)(kycEndpoints.ValidateUserBasic)
		route.Path("/kyc/social/users/{userID}/checks/basic").Methods("PUT").Handler(kycValidateUserBasicIDHandler)
		/********************* (END) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/

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
		logger.Info(ctx, "addr", httpAddrAccount, "interface", "self-service")

		var route = mux.NewRouter()

		// Account
		var configureAccountHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, audienceRequired, account.MakeAccountHandler, logger)

		var updatePasswordHandler = configureAccountHandler(accountEndpoints.UpdatePassword)
		var getCredentialsHandler = configureAccountHandler(accountEndpoints.GetCredentials)
		var getCredentialRegistratorsHandler = configureAccountHandler(accountEndpoints.GetCredentialRegistrators)
		var deleteCredentialHandler = configureAccountHandler(accountEndpoints.DeleteCredential)
		var updateLabelCredentialHandler = configureAccountHandler(accountEndpoints.UpdateLabelCredential)
		var moveCredentialHandler = configureAccountHandler(accountEndpoints.MoveCredential)
		var getAccountHandler = configureAccountHandler(accountEndpoints.GetAccount)
		var updateAccountHandler = configureAccountHandler(accountEndpoints.UpdateAccount)
		var deleteAccountHandler = configureAccountHandler(accountEndpoints.DeleteAccount)
		var getConfigurationHandler = configureAccountHandler(accountEndpoints.GetConfiguration)
		var getProfileHandler = configureAccountHandler(accountEndpoints.GetProfile)
		var sendVerifyEmailHandler = configureAccountHandler(accountEndpoints.SendVerifyEmail)
		var sendVerifyPhoneNumberHandler = configureAccountHandler(accountEndpoints.SendVerifyPhoneNumber)
		var cancelEmailChangeHandler = configureAccountHandler(accountEndpoints.CancelEmailChange)
		var cancelPhoneNumberChangeHandler = configureAccountHandler(accountEndpoints.CancelPhoneNumberChange)
		var getLinkedAccountsHandler = configureAccountHandler(accountEndpoints.GetLinkedAccounts)
		var deleteLinkedAccountHandler = configureAccountHandler(accountEndpoints.DeleteLinkedAccount)

		route.Path("/account").Methods("GET").Handler(getAccountHandler)
		route.Path("/account").Methods("POST").Handler(updateAccountHandler)
		route.Path("/account").Methods("DELETE").Handler(deleteAccountHandler)

		route.Path("/account/configuration").Methods("GET").Handler(getConfigurationHandler)
		route.Path("/account/profile").Methods("GET").Handler(getProfileHandler)

		route.Path("/account/credentials").Methods("GET").Handler(getCredentialsHandler)
		route.Path("/account/credentials/password").Methods("POST").Handler(updatePasswordHandler)
		route.Path("/account/credentials/registrators").Methods("GET").Handler(getCredentialRegistratorsHandler)
		route.Path("/account/credentials/{credentialID}").Methods("DELETE").Handler(deleteCredentialHandler)
		route.Path("/account/credentials/{credentialID}").Methods("PUT").Handler(updateLabelCredentialHandler)
		route.Path("/account/credentials/{credentialID}/after/{previousCredentialID}").Methods("POST").Handler(moveCredentialHandler)

		route.Path("/account/verify-email").Methods("PUT").Handler(sendVerifyEmailHandler)
		route.Path("/account/verify-phone-number").Methods("PUT").Handler(sendVerifyPhoneNumberHandler)

		route.Path("/account/cancel-email-change").Methods("PUT").Handler(cancelEmailChangeHandler)
		route.Path("/account/cancel-phone-number-change").Methods("PUT").Handler(cancelPhoneNumberChangeHandler)

		route.Path("/account/linked-accounts").Methods("GET").Handler(getLinkedAccountsHandler)
		route.Path("/account/linked-accounts/{providerAlias}").Methods("DELETE").Handler(deleteLinkedAccountHandler)

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
		logger.Info(ctx, "addr", httpAddrMobile, "interface", "mobile")

		var route = mux.NewRouter()

		// Mobile
		var getUserInfoHandler = configureHandler(keycloakb.ComponentName, ComponentID, idGenerator, keycloakClient, mobileAudienceRequired, mobile.MakeMobileHandler, logger)(mobileEndpoints.GetUserInformation)

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
		logger.Info(ctx, "addr", httpAddrRegister, "interface", "register")

		var route = mux.NewRouter()

		// Configuration
		var getConfigurationHandler = configurePublicRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, logger)(registerEndpoints.GetConfiguration)
		var getUserProfileHandler = configurePublicRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, logger)(registerEndpoints.GetUserProfile)

		// Handler with recaptcha token
		var registerUserHandler = configureRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, recaptchaURL, recaptchaSecret, logger)(registerEndpoints.RegisterUser)
		route.Path("/register/user").Methods("POST").Handler(registerUserHandler)
		route.Path("/register/user/profile").Methods("GET").Handler(getUserProfileHandler)

		// Handler with recaptcha token
		var registerCorpUserHandler = configureRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, recaptchaURL, recaptchaSecret, logger)(registerEndpoints.RegisterCorpUser)
		var getCorpUserProfileHandler = configurePublicRegisterHandler(keycloakb.ComponentName, ComponentID, idGenerator, logger)(registerEndpoints.GetCorpUserProfile)
		route.Path("/register/realms/{corpRealm}/user").Methods("POST").Handler(registerCorpUserHandler)
		route.Path("/register/realms/{corpRealm}/user/profile").Methods("GET").Handler(getCorpUserProfileHandler)

		route.Path("/register/config").Methods("GET").Handler(getConfigurationHandler)

		var handler http.Handler = route

		if accessLogsEnabled {
			handler = commonhttp.MakeAccessLogHandler(accessLogger, handler)
		}

		c := cors.New(corsOptions)
		handler = c.Handler(handler)

		errc <- http.ListenAndServe(httpAddrRegister, handler)
	}()

	// HTTP configuration server (Configuration API)
	go func() {
		logger := log.With(logger, "transport", "http")
		logger.Info(ctx, "addr", httpAddrConfiguration, "interface", "configuration")

		route := mux.NewRouter()

		getIdentificationURIHandler := configurePublicConfigurationHandler(keycloakb.ComponentName, ComponentID, idGenerator, logger)(configurationEndpoints.GetIdentificationURI)
		route.Path("/configuration/realms/{realm}/identification").Methods("GET").Handler(getIdentificationURIHandler)

		var handler http.Handler = route

		if accessLogsEnabled {
			handler = commonhttp.MakeAccessLogHandler(accessLogger, handler)
		}

		c := cors.New(corsOptions)
		handler = c.Handler(handler)

		errc <- http.ListenAndServe(httpAddrConfiguration, handler)
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
	v.SetDefault(cfgLogEventRate, 1000)

	// Access Logs
	v.SetDefault(cfgAccessLogsEnabled, true)

	// Publishing
	v.SetDefault(cfgHTTPAddrInternal, defaultPublishingIP+":8888")
	v.SetDefault(cfgHTTPAddrManagement, defaultPublishingIP+":8877")
	v.SetDefault(cfgHTTPAddrAccount, defaultPublishingIP+":8866")
	v.SetDefault(cfgHTTPAddrRegister, defaultPublishingIP+":8855")
	v.SetDefault(cfgHTTPAddrMobile, defaultPublishingIP+":8844")
	v.SetDefault(cfgHTTPAddrMonitoring, defaultPublishingIP+":8899")
	v.SetDefault(cfgHTTPAddrConfiguration, defaultPublishingIP+":8870")

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
	v.SetDefault(cfgDbArchiveAesGcmTagSize, 16)
	v.SetDefault(cfgDbArchiveAesGcmKey, "")

	// CORS configuration
	v.SetDefault(cfgAllowedOrigins, []string{})
	v.SetDefault(cfgAllowedMethods, []string{})
	v.SetDefault(cfgAllowCredentials, true)
	v.SetDefault(cfgAllowedHeaders, []string{})
	v.SetDefault(cfgExposedHeaders, []string{})
	v.SetDefault(cfgDebug, false)

	// Accounting default.
	v.SetDefault(cfgAddrAccounting, "http://0.0.0.0:8940")
	v.SetDefault(cfgAccountingTimeout, "5s")

	//Storage custom configuration in DB (read/write)
	database.ConfigureDbDefault(v, cfgConfigRwDbParams, "CT_BRIDGE_DB_CONFIG_RW_USERNAME", "CT_BRIDGE_DB_CONFIG_RW_PASSWORD")

	//Storage custom configuration in DB (read only)
	database.ConfigureDbDefault(v, cfgConfigRoDbParams, "CT_BRIDGE_DB_CONFIG_RO_USERNAME", "CT_BRIDGE_DB_CONFIG_RO_PASSWORD")

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
	v.SetDefault(cfgRateKeyRegister, 1000)
	v.SetDefault(cfgRateKeyTasks, 10)
	v.SetDefault(cfgRateKeySupport, 10)
	v.SetDefault(cfgRateKeyKYC, 1000)

	// Debug routes enabled.
	v.SetDefault(cfgPprofRouteEnabled, true)

	// Liveness probe
	v.SetDefault("livenessprobe-http-timeout", 900)
	v.SetDefault("livenessprobe-cache-duration", 500)
	v.SetDefault("livenessprobe-audit-timeout", 3000)

	// Register parameters
	v.SetDefault(cfgRegisterRealm, "trustid")
	v.SetDefault(cfgRegisterMaxInactiveLock, "720h") // 30 days
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

	// Validation rules
	v.SetDefault(cfgValidationRules, map[string]string{})

	// Onboarding realm overrides
	v.SetDefault(cfgOnboardingRealmOverrides, map[string]string{})

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

	v.BindEnv(cfgValidationBasicAuthToken, "CT_BRIDGE_VALIDATION_BASIC_AUTH")
	censoredParameters[cfgValidationBasicAuthToken] = true

	v.BindEnv(cfgDbArchiveAesGcmKey, "CT_BRIDGE_DB_ARCHIVE_AES_KEY")
	censoredParameters[cfgDbArchiveAesGcmKey] = true

	// Load and log config.
	v.SetConfigFile(v.GetString(cfgConfigFile))
	var err = v.ReadInConfig()
	if err != nil {
		logger.Error(ctx, "err", err)
	}

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

func toDbLogger(logger log.Logger, config *database.DbConfig) log.Logger {
	return log.With(logger, "unit", "db", "db-name", config.Database)
}

// configureHandler is a generic configuration handler with support of correlationID and OIDC validation
func configureHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client, audienceRequired string, baseHandler func(_ endpoint.Endpoint, _ log.Logger) *http_transport.Server, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = baseHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, nil, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

// configureValidationHandler uses a basic authentication
func configureValidationHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, expectedToken string, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = validation.MakeValidationHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, nil, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPBasicAuthenticationMW(expectedToken, logger)(handler)
		return handler
	}
}

func configureRightsHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, authorizationManager security.AuthorizationManager, keycloakClient *keycloakapi.Client, audienceRequired string, logger log.Logger) http.Handler {
	var handler http.Handler
	handler = commonhttp.MakeRightsHandler(authorizationManager)
	handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, nil, logger, ComponentName, ComponentID)(handler)
	handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
	return handler
}

// configureKYCHandler pre-checks the realm to allow access only for configured ones
func configureKYCHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, keycloakClient *keycloakapi.Client,
	audienceRequired string, availabilityChecker middleware.EndpointAvailabilityChecker,
	verifyAvailableChecks bool, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = kyc.MakeKYCHandler(endpoint, logger)
		if verifyAvailableChecks {
			handler = middleware.MakeEndpointAvailableCheckMW(availabilityChecker, logger)(handler)
		}
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, nil, logger, ComponentName, ComponentID)(handler)
		handler = middleware.MakeHTTPOIDCTokenValidationMW(keycloakClient, audienceRequired, logger)(handler)
		return handler
	}
}

// configureRegisterHandler uses a RECAPTCHA validation
func configureRegisterHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, recaptchaURL, recaptchaSecret string, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = register.MakeRegisterHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, nil, logger, ComponentName, ComponentID)(handler)
		handler = register.MakeHTTPRecaptchaValidationMW(recaptchaURL, recaptchaSecret, logger)(handler)
		return handler
	}
}

// configurePublicRegisterHandler is a public handler. No authorization is checked here
func configurePublicRegisterHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = register.MakeRegisterHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, nil, logger, ComponentName, ComponentID)(handler)
		return handler
	}
}

// configurePublicRegisterHandler is a public handler. No authorization is checked here
func configurePublicConfigurationHandler(ComponentName string, ComponentID string, idGenerator idgenerator.IDGenerator, logger log.Logger) func(endpoint endpoint.Endpoint) http.Handler {
	return func(endpoint endpoint.Endpoint) http.Handler {
		var handler http.Handler
		handler = conf.MakeConfigurationHandler(endpoint, logger)
		handler = middleware.MakeHTTPCorrelationIDMW(idGenerator, nil, logger, ComponentName, ComponentID)(handler)
		return handler
	}
}

func createConfigurationDBModule(configDBConn sqltypes.CloudtrustDB, logger log.Logger) keycloakb.ConfigurationDBModule {
	var configDBModule keycloakb.ConfigurationDBModule
	{
		configDBModule = keycloakb.NewConfigurationDBModule(configDBConn, logger)
	}
	return configDBModule
}

func prepareEndpoint(e cs.Endpoint, endpointName string, logger log.Logger, rateLimit int) endpoint.Endpoint {
	e = middleware.MakeEndpointLoggingMW(log.With(log.With(logger, "mw", "request"), "endpoint", endpointName))(e)
	return keycloakb.LimitRate(e, rateLimit)
}

func prepareEndpointWithoutLogging(e cs.Endpoint, rateLimit int) endpoint.Endpoint {
	return keycloakb.LimitRate(e, rateLimit)
}
