package register

import (
	"context"
	"errors"
	"time"

	"github.com/cloudtrust/keycloak-client/toolbox"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/validation"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation) (string, error)
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	DeleteUser(accessToken string, realmName, userID string) error
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	SendEmail(accessToken string, reqRealmName string, realmName string, emailRep kc.EmailRepresentation) error
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	GetConfigurations(context.Context, string) (configuration.RealmConfiguration, configuration.RealmAdminConfiguration, error)
	GetConfiguration(context.Context, string) (configuration.RealmConfiguration, error)
}

// OnboardingModule is the interface for the onboarding process
type OnboardingModule interface {
	OnboardingAlreadyCompleted(kc.UserRepresentation) (bool, error)
	SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, username string,
		onboardingClientID string, onboardingRedirectURI string, themeRealmName string, reminder bool, lifespan *int) error
	CreateUser(ctx context.Context, accessToken, realmName, targetRealmName string, kcUser *kc.UserRepresentation) (string, error)
}

// GlnVerifier interface allows to check validity of a GLN
type GlnVerifier interface {
	ValidateGLN(firstName, lastName, gln string) error
}

// Component is the register component interface.
type Component interface {
	RegisterUser(ctx context.Context, targetRealmName string, customerRealmName string, user apiregister.UserRepresentation) error
	GetConfiguration(ctx context.Context, realmName string) (apiregister.ConfigurationRepresentation, error)
}

// NewComponent returns component.
func NewComponent(keycloakClient KeycloakClient, tokenProvider toolbox.OidcTokenProvider, usersDBModule keycloakb.UsersDetailsDBModule,
	configDBModule ConfigurationDBModule, eventsDBModule database.EventsDBModule, onboardingModule OnboardingModule, glnVerifier GlnVerifier, logger keycloakb.Logger) Component {
	return &component{
		keycloakClient:   keycloakClient,
		tokenProvider:    tokenProvider,
		usersDBModule:    usersDBModule,
		configDBModule:   configDBModule,
		eventsDBModule:   eventsDBModule,
		onboardingModule: onboardingModule,
		glnVerifier:      glnVerifier,
		logger:           logger,
	}
}

// Component is the management component.
type component struct {
	keycloakClient   KeycloakClient
	tokenProvider    toolbox.OidcTokenProvider
	usersDBModule    keycloakb.UsersDetailsDBModule
	configDBModule   ConfigurationDBModule
	eventsDBModule   database.EventsDBModule
	onboardingModule OnboardingModule
	glnVerifier      GlnVerifier
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

func (c *component) RegisterUser(ctx context.Context, targetRealmName string, customerRealmName string, user apiregister.UserRepresentation) error {
	// Get an OIDC token to be able to request Keycloak
	var accessToken string
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, targetRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return err
	}

	// Get Realm configuration from database
	realmConf, realmAdminConf, err := c.configDBModule.GetConfigurations(ctx, targetRealmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm configuration from database", "err", err.Error())
		return err
	}

	if realmAdminConf.SelfRegisterEnabled == nil || !*realmAdminConf.SelfRegisterEnabled {
		return errorhandler.CreateEndpointNotEnabled("selfRegister")
	}

	if (realmConf.SelfRegisterGroupNames == nil || len(*realmConf.SelfRegisterGroupNames) == 0) ||
		(realmConf.OnboardingRedirectURI == nil || *realmConf.OnboardingRedirectURI == "") ||
		(realmConf.OnboardingClientID == nil || *realmConf.OnboardingClientID == "") {
		return errorhandler.CreateEndpointNotEnabled(constants.MsgErrNotConfigured)
	}

	if realmAdminConf.ShowGlnEditing != nil && *realmAdminConf.ShowGlnEditing && user.BusinessID != nil {
		if glnErr := c.glnVerifier.ValidateGLN(*user.FirstName, *user.LastName, *user.BusinessID); glnErr != nil {
			return glnErr
		}
	} else {
		user.BusinessID = nil
	}

	kcUser, err := c.getUserByEmailIfDuplicateNotAllowed(ctx, accessToken, targetRealmName, *user.Email)
	if err != nil {
		return err
	}

	// If user already exists...
	if kcUser != nil {
		alreadyOnboarded, err := c.onboardingModule.OnboardingAlreadyCompleted(*kcUser)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Invalid OnboardingCompleted attribute for user", "userID", kcUser.ID, "err", err.Error())
			return err
		}

		// Error if user is already onboarded
		if alreadyOnboarded {
			user.Username = kcUser.Username
			return c.sendAlreadyExistsEmail(ctx, accessToken, targetRealmName, customerRealmName, user, *kcUser.CreatedTimestamp,
				"register-already-onboarded.ftl")
		}

		if attrb := kcUser.GetAttributeString(constants.AttrbSource); attrb != nil && *attrb != "register" {
			user.Username = kcUser.Username
			return c.sendAlreadyExistsEmail(ctx, accessToken, targetRealmName, customerRealmName, user, *kcUser.CreatedTimestamp,
				"register-thirdparty-created.ftl", "src", *attrb)
		}

		// Else delete this not fully onboarded user to be able to perform a fully new onboarding
		err = c.deleteUser(ctx, accessToken, targetRealmName, *kcUser.ID)
		if err != nil {
			return err
		}
	}

	// Create new user
	userID, username, err := c.createUser(ctx, accessToken, targetRealmName, user, *realmConf.SelfRegisterGroupNames)
	if err != nil {
		return err
	}

	// Send email
	var onboardingRedirectURI = *realmConf.OnboardingRedirectURI

	if targetRealmName != customerRealmName {
		onboardingRedirectURI += "?customerRealm=" + customerRealmName
	}

	var lifespan = 3600 // 1 hour
	err = c.onboardingModule.SendOnboardingEmail(ctx, accessToken, targetRealmName, userID, username,
		*realmConf.OnboardingClientID, onboardingRedirectURI, customerRealmName, false, &lifespan)
	if err != nil {
		return err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "REGISTER_USER", database.CtEventRealmName, targetRealmName, database.CtEventUserID, userID, database.CtEventUsername, username)

	return nil
}

func (c *component) sendAlreadyExistsEmail(ctx context.Context, accessToken string, reqRealmName string, realmName string,
	user apiregister.UserRepresentation, creationTimestamp int64, templateName string, paramKV ...string) error {
	var cantRegisterSubjectKey = "cantRegisterSubject"
	var params = make(map[string]string)

	for i := 0; i+1 < len(paramKV); i += 2 {
		params[paramKV[i]] = paramKV[i+1]
	}

	// Add creation date
	var creation = time.Unix(creationTimestamp/1000, 0)
	params["creationDate"] = creation.Format("02.01.2006")
	params["creationHour"] = creation.Format("15:04:05")

	c.logger.Info(ctx, "msg", "User is trying to register again", "user", *user.Username)
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

func (c *component) createUser(ctx context.Context, accessToken string, realmName string, user apiregister.UserRepresentation, groupNames []string) (string, string, error) {
	var kcUser = user.ConvertToKeycloak()
	kcUser.SetAttributeString(constants.AttrbSource, "register")

	// Set groups
	groupIDs, err := c.convertGroupNamesToGroupIDs(accessToken, realmName, groupNames)
	if err != nil {
		c.logger.Error(ctx, "msg", "Failed to convert groupNames to groupIDs", "err", err.Error())
		return "", "", err
	}
	kcUser.Groups = &groupIDs

	_, err = c.onboardingModule.CreateUser(ctx, accessToken, realmName, realmName, &kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
		return "", "", err
	}

	// Store user details in database
	err = c.usersDBModule.StoreOrUpdateUserDetails(ctx, realmName, dto.DBUser{
		UserID:               kcUser.ID,
		BirthLocation:        user.BirthLocation,
		Nationality:          user.Nationality,
		IDDocumentType:       user.IDDocumentType,
		IDDocumentNumber:     user.IDDocumentNumber,
		IDDocumentExpiration: user.IDDocumentExpiration,
		IDDocumentCountry:    user.IDDocumentCountry,
	})

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store user details in database", "err", err.Error())
		return "", "", err
	}

	return *kcUser.ID, *kcUser.Username, nil
}

func (c *component) getUserByEmailIfDuplicateNotAllowed(ctx context.Context, accessToken string, realmName string, email string) (*kc.UserRepresentation, error) {
	var kcRealm, err = c.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm from Keycloak", "err", err.Error(), "realm", realmName)
		return nil, err
	}

	if kcRealm.DuplicateEmailsAllowed != nil && *kcRealm.DuplicateEmailsAllowed {
		// Duplicate email is allowed in the realm... don't need to check if email is already in use
		return nil, nil
	}

	// Add '=' at beginning of the email address to ensure that GetUsers retrieves an account with the exact provided email address
	kcUsers, err := c.keycloakClient.GetUsers(accessToken, realmName, realmName, "email", "="+email)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user from keycloak", "err", err.Error())
		return nil, err
	}

	if kcUsers.Count == nil || *kcUsers.Count == 0 {
		return nil, nil
	}

	kcUser := kcUsers.Users[0]
	keycloakb.ConvertLegacyAttribute(&kcUser)

	return &kcUser, nil
}

func (c *component) deleteUser(ctx context.Context, accessToken string, realmName string, userID string) error {
	err := c.keycloakClient.DeleteUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to delete user", "userID", userID, "err", err.Error())
		return err
	}

	err = c.usersDBModule.DeleteUserDetails(ctx, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to delete user infos", "userID", userID, "err", err.Error())
		return err
	}

	return nil
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
