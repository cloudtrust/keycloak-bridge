package register

import (
	"context"
	"errors"
	"time"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/validation"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	SendEmail(accessToken string, reqRealmName string, realmName string, emailRep kc.EmailRepresentation) error
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	GetConfigurations(context.Context, string) (configuration.RealmConfiguration, configuration.RealmAdminConfiguration, error)
	GetConfiguration(context.Context, string) (configuration.RealmConfiguration, error)
}

// ExistingUserHandler is used by OnboardingModule
type ExistingUserHandler func(username string, createdTimestamp int64, thirdParty *string) error

// OnboardingModule is the interface for the onboarding process
type OnboardingModule interface {
	SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, username string, onboardingClientID string,
		onboardingRedirectURI string, themeRealmName string, reminder bool, paramKV ...string) error
	CreateUser(ctx context.Context, accessToken, realmName, targetRealmName string, kcUser *kc.UserRepresentation) (string, error)
	ProcessAlreadyExistingUserCases(ctx context.Context, accessToken string, targetRealmName string, userEmail string, requestingSource string, handler func(username string, createdTimestamp int64, thirdParty *string) error) error
	ComputeRedirectURI(ctx context.Context, accessToken string, realmName string, userID string, username string,
		onboardingClientID string, onboardingRedirectURI string) (string, error)
}

// GlnVerifier interface allows to check validity of a GLN
type GlnVerifier interface {
	ValidateGLN(firstName, lastName, gln string) error
}

// UserProfileCache interface
type UserProfileCache interface {
	GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error)
}

// ContextKeyManager interface
type ContextKeyManager interface {
	GetOverride(realm string, contextKey string) (keycloakb.ContextKeyParameters, bool)
}

// Component is the register component interface.
type Component interface {
	RegisterUser(ctx context.Context, targetRealmName string, customerRealmName string, user apiregister.UserRepresentation, contextKey *string) (string, error)
	GetConfiguration(ctx context.Context, realmName string) (apiregister.ConfigurationRepresentation, error)
	GetUserProfile(ctx context.Context, realmName string) (apicommon.ProfileRepresentation, error)
}

var (
	errAccountAlreadyExists = errors.New("")
)

// NewComponent returns component.
func NewComponent(keycloakClient KeycloakClient, tokenProvider toolbox.OidcTokenProvider, profileCache UserProfileCache,
	configDBModule ConfigurationDBModule, eventsDBModule database.EventsDBModule, onboardingModule OnboardingModule, glnVerifier GlnVerifier,
	contextKeyManager ContextKeyManager, logger keycloakb.Logger) Component {
	return &component{
		keycloakClient:   keycloakClient,
		tokenProvider:    tokenProvider,
		profileCache:     profileCache,
		configDBModule:   configDBModule,
		eventsDBModule:   eventsDBModule,
		onboardingModule: onboardingModule,
		glnVerifier:      glnVerifier,
		contextKeyMgr:    contextKeyManager,
		logger:           logger,
	}
}

// Component is the management component.
type component struct {
	keycloakClient   KeycloakClient
	tokenProvider    toolbox.OidcTokenProvider
	profileCache     UserProfileCache
	configDBModule   ConfigurationDBModule
	eventsDBModule   database.EventsDBModule
	onboardingModule OnboardingModule
	glnVerifier      GlnVerifier
	contextKeyMgr    ContextKeyManager
	logger           keycloakb.Logger
}

func (c *component) getSupportedLocales(ctx context.Context, realmName string) (*[]string, error) {
	var accessToken string
	var err error

	// Get an OIDC token to be able to request Keycloak
	if accessToken, err = c.tokenProvider.ProvideToken(ctx); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return nil, err
	}

	var realmConf kc.RealmRepresentation
	if realmConf, err = c.keycloakClient.GetRealm(accessToken, realmName); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get realm configuration", "err", err.Error(), "realm", realmName)
		return nil, err
	}
	if realmConf.InternationalizationEnabled != nil && *realmConf.InternationalizationEnabled {
		return realmConf.SupportedLocales, nil
	}
	return nil, nil
}

func (c *component) GetConfiguration(ctx context.Context, realmName string) (apiregister.ConfigurationRepresentation, error) {
	// Get Realm configuration from database
	var realmConf, realmAdminConf, err = c.configDBModule.GetConfigurations(ctx, realmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm configuration from database", "err", err.Error())
		return apiregister.ConfigurationRepresentation{}, err
	}

	var supportedLocales *[]string
	if supportedLocales, err = c.getSupportedLocales(ctx, realmName); err != nil {
		return apiregister.ConfigurationRepresentation{}, err
	}

	return apiregister.ConfigurationRepresentation{
		RedirectCancelledRegistrationURL: realmConf.RedirectCancelledRegistrationURL,
		Mode:                             realmAdminConf.Mode,
		Theme:                            realmAdminConf.Theme,
		SupportedLocales:                 supportedLocales,
		SelfRegisterEnabled:              realmAdminConf.SelfRegisterEnabled,
	}, nil
}

func (c *component) GetUserProfile(ctx context.Context, realmName string) (apicommon.ProfileRepresentation, error) {
	var profile, err = c.profileCache.GetRealmUserProfile(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user profile", "err", err.Error())
		return apicommon.ProfileRepresentation{}, err
	}

	return apicommon.ProfileToApi(profile, apiName), nil
}

func (c *component) RegisterUser(ctx context.Context, targetRealmName string, customerRealmName string, user apiregister.UserRepresentation, contextKey *string) (string, error) {
	// Get an OIDC token to be able to request Keycloak
	var accessToken string
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, targetRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return "", err
	}

	// Get Realm configuration from database
	realmConf, realmAdminConf, err := c.configDBModule.GetConfigurations(ctx, targetRealmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm configuration from database", "err", err.Error())
		return "", err
	}

	var redirect = false
	var ctxOverride keycloakb.ContextKeyParameters
	if contextKey != nil {
		var ok bool
		if ctxOverride, ok = c.contextKeyMgr.GetOverride(customerRealmName, *contextKey); !ok {
			c.logger.Info(ctx, "msg", "Invalid context key", "context-key", *contextKey)
			return "", errorhandler.CreateBadRequestError(errorhandler.MsgErrInvalidParam + ".context-key")
		}
		if ctxOverride.OnboardingClientID != nil {
			realmConf.OnboardingClientID = ctxOverride.OnboardingClientID
		}
		if ctxOverride.OnboardingRedirectURI != nil {
			realmConf.OnboardingRedirectURI = ctxOverride.OnboardingRedirectURI
		}
		if ctxOverride.RedirectMode != nil {
			redirect = *ctxOverride.RedirectMode
		}
	}

	if realmAdminConf.SelfRegisterEnabled == nil || !*realmAdminConf.SelfRegisterEnabled {
		return "", errorhandler.CreateEndpointNotEnabled("selfRegister")
	}

	if (realmConf.SelfRegisterGroupNames == nil || len(*realmConf.SelfRegisterGroupNames) == 0) ||
		(realmConf.OnboardingRedirectURI == nil || *realmConf.OnboardingRedirectURI == "") ||
		(realmConf.OnboardingClientID == nil || *realmConf.OnboardingClientID == "") {
		return "", errorhandler.CreateEndpointNotEnabled(constants.MsgErrNotConfigured)
	}

	if realmAdminConf.ShowGlnEditing != nil && *realmAdminConf.ShowGlnEditing && user.BusinessID != nil {
		if glnErr := c.glnVerifier.ValidateGLN(*user.FirstName, *user.LastName, *user.BusinessID); glnErr != nil {
			return "", glnErr
		}
	} else {
		user.BusinessID = nil
	}

	var onboardingRedirectURI = *realmConf.OnboardingRedirectURI

	if targetRealmName != customerRealmName {
		onboardingRedirectURI += "?customerRealm=" + customerRealmName
	}

	var redirectURL string
	var kcUser kc.UserRepresentation
	if redirect {
		kcUser, err = c.registerUserRedirectMode(ctx, accessToken, targetRealmName, customerRealmName, user, realmConf, onboardingRedirectURI)
		if err != nil {
			return "", err
		}
		redirectURL, err = c.onboardingModule.ComputeRedirectURI(ctx, accessToken, targetRealmName, *kcUser.ID, *kcUser.Username, *realmConf.OnboardingClientID, onboardingRedirectURI)
	} else {
		kcUser, err = c.registerUser(ctx, accessToken, targetRealmName, customerRealmName, user, realmConf, onboardingRedirectURI)
	}
	if err == errAccountAlreadyExists {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "REGISTER_USER", database.CtEventRealmName, targetRealmName, database.CtEventUserID, *kcUser.ID, database.CtEventUsername, *kcUser.Username)

	return redirectURL, nil
}

func (c *component) registerUser(ctx context.Context, accessToken string, targetRealmName string, customerRealmName string, user apiregister.UserRepresentation, realmConf configuration.RealmConfiguration, onboardingRedirectURI string) (kc.UserRepresentation, error) {
	err := c.onboardingModule.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, *user.Email, "register", func(username string, createdTimestamp int64, thirdParty *string) error {
		var err error
		if thirdParty == nil {
			err = c.sendAlreadyExistsEmail(ctx, accessToken, targetRealmName, customerRealmName, user, username, createdTimestamp, "register-already-onboarded.ftl")
		} else {
			err = c.sendAlreadyExistsEmail(ctx, accessToken, targetRealmName, customerRealmName, user, username, createdTimestamp, "register-thirdparty-created.ftl", "src", *thirdParty)
		}
		if err != nil {
			return err
		}
		return errAccountAlreadyExists
	})
	if err != nil {
		return kc.UserRepresentation{}, err
	}

	// Create new user

	kcUser, err := c.createUser(ctx, accessToken, targetRealmName, user, *realmConf.SelfRegisterGroupNames, false)
	if err != nil {
		return kc.UserRepresentation{}, err
	}

	// Send email
	var paramKV = []string{"lifespan", "3600"} // 1 hour
	return kcUser, c.onboardingModule.SendOnboardingEmail(ctx, accessToken, targetRealmName, *kcUser.ID, *kcUser.Username,
		*realmConf.OnboardingClientID, onboardingRedirectURI, customerRealmName, false, paramKV...)
}

func (c *component) registerUserRedirectMode(ctx context.Context, accessToken string, targetRealmName string, customerRealmName string, user apiregister.UserRepresentation, realmConf configuration.RealmConfiguration, onboardingRedirectURI string) (kc.UserRepresentation, error) {
	// Create new user
	kcUser, err := c.createUser(ctx, accessToken, targetRealmName, user, *realmConf.SelfRegisterGroupNames, true)
	if err != nil {
		return kc.UserRepresentation{}, err
	}

	return kcUser, err
}

func (c *component) sendAlreadyExistsEmail(ctx context.Context, accessToken string, reqRealmName string, realmName string,
	user apiregister.UserRepresentation, username string, creationTimestamp int64, templateName string, paramKV ...string) error {
	var cantRegisterSubjectKey = "cantRegisterSubject"
	var params = make(map[string]string)

	for i := 0; i+1 < len(paramKV); i += 2 {
		params[paramKV[i]] = paramKV[i+1]
	}

	// Add creation date
	var creation = time.Unix(creationTimestamp/1000, 0)
	switzerlandLocation, err := time.LoadLocation("Europe/Zurich")
	if err != nil {
		creation = creation.UTC()
		params["creationDate"] = creation.Format("02.01.2006")
		params["creationHour"] = creation.Format("15:04:05") + " UTC"
	} else {
		creation = creation.In(switzerlandLocation)
		params["creationDate"] = creation.Format("02.01.2006")
		params["creationHour"] = creation.Format("15:04:05")
	}

	c.logger.Info(ctx, "msg", "User is trying to register again", "user", username)
	return c.keycloakClient.SendEmail(accessToken, reqRealmName, realmName, kc.EmailRepresentation{
		Recipient: user.Email,
		Theming: &kc.EmailThemingRepresentation{
			SubjectKey:         &cantRegisterSubjectKey,
			SubjectParameters:  &[]string{},
			Template:           &templateName,
			TemplateParameters: &params,
			Locale:             user.Locale,
		},
	})
}

func (c *component) createUser(ctx context.Context, accessToken string, realmName string, user apiregister.UserRepresentation, groupNames []string, needEmailToValidate bool) (kc.UserRepresentation, error) {
	var kcUser = user.ConvertToKeycloak()
	kcUser.SetAttributeString(constants.AttrbSource, "register")

	if needEmailToValidate {
		kcUser.SetAttributeString(constants.AttrbEmailToValidate, *kcUser.Email)
		kcUser.Email = nil
	}

	// Set groups
	groupIDs, err := c.convertGroupNamesToGroupIDs(accessToken, realmName, groupNames)
	if err != nil {
		c.logger.Error(ctx, "msg", "Failed to convert groupNames to groupIDs", "err", err.Error())
		return kc.UserRepresentation{}, err
	}
	kcUser.Groups = &groupIDs

	_, err = c.onboardingModule.CreateUser(ctx, accessToken, realmName, realmName, &kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
		return kc.UserRepresentation{}, err
	}

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store user details in database", "err", err.Error())
		return kc.UserRepresentation{}, err
	}

	return kcUser, nil
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventsDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		keycloakb.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}

func (c *component) convertGroupNamesToGroupIDs(accessToken string, realmName string, groupNames []string) ([]string, error) {
	var groups []kc.GroupRepresentation

	groups, err := c.keycloakClient.GetGroups(accessToken, realmName)
	if err != nil {
		return nil, err
	}

	var res []string
	for _, group := range groups {
		if validation.IsStringInSlice(groupNames, *group.Name) {
			res = append(res, *group.ID)
		}
	}

	if len(res) != len(groupNames) {
		return nil, errors.New("at least one group name could not be found")
	}
	return res, nil
}
