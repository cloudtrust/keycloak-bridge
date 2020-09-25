package register

import (
	"context"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// TrustIDAuthToken struct
type TrustIDAuthToken struct {
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at"`
}

// ToJSON converts TrustIDAuthToken to its JSON representation
func (t TrustIDAuthToken) ToJSON() string {
	var authBytes, _ = json.Marshal(t)
	return string(authBytes)
}

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation) (string, error)
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	ExecuteActionsEmail(accessToken string, realmName string, userID string, actions []string, paramKV ...string) error
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	GetConfigurations(context.Context, string) (configuration.RealmConfiguration, configuration.RealmAdminConfiguration, error)
	GetConfiguration(context.Context, string) (configuration.RealmConfiguration, error)
}

// RealmRegisterConfiguration struct
type RealmRegisterConfiguration struct {
	Realm           string
	EndUserGroups   []string
	EnduserClientID string
	SsePublicURL    string
	endUserGroupIDs []string
}

// ComponentBuilder interface
type ComponentBuilder interface {
	Build() Component
	AddTargetRealm(realmConf RealmRegisterConfiguration) error
}

type componentBuilder struct {
	component *component
}

// NewComponentBuilder returns a builder for the management component.
func NewComponentBuilder(keycloakURL string, keycloakClient KeycloakClient, tokenProvider toolbox.OidcTokenProvider, usersDBModule keycloakb.UsersDetailsDBModule,
	configDBModule ConfigurationDBModule, eventsDBModule database.EventsDBModule, logger internal.Logger) ComponentBuilder {
	var component = &component{
		keycloakURL:         keycloakURL,
		realmConfigurations: make(map[string]RealmRegisterConfiguration),
		keycloakClient:      keycloakClient,
		tokenProvider:       tokenProvider,
		usersDBModule:       usersDBModule,
		configDBModule:      configDBModule,
		eventsDBModule:      eventsDBModule,
		logger:              logger,
	}
	return &componentBuilder{component: component}
}

func (r *componentBuilder) Build() Component {
	return r.component
}

func (r *componentBuilder) AddTargetRealm(realmConf RealmRegisterConfiguration) error {
	return r.component.addTargetRealm(realmConf)
}

// Component is the register component interface.
type Component interface {
	RegisterUser(ctx context.Context, targetRealmName, clientRealmName string, user apiregister.UserRepresentation) (string, error)
	GetConfiguration(ctx context.Context, realmName string) (apiregister.ConfigurationRepresentation, error)
}

// Component is the management component.
type component struct {
	keycloakURL         string
	realmConfigurations map[string]RealmRegisterConfiguration
	keycloakClient      KeycloakClient
	tokenProvider       toolbox.OidcTokenProvider
	usersDBModule       keycloakb.UsersDetailsDBModule
	configDBModule      ConfigurationDBModule
	eventsDBModule      database.EventsDBModule
	logger              internal.Logger
}

func (c *component) addTargetRealm(realmConf RealmRegisterConfiguration) error {
	var IDs, err = c.convertNamesToIDs(realmConf)
	if err == nil {
		realmConf.endUserGroupIDs = IDs
		c.realmConfigurations[realmConf.Realm] = realmConf
	}
	return err
}

func (c *component) convertNamesToIDs(realmConf RealmRegisterConfiguration) ([]string, error) {
	var accessToken, err = c.tokenProvider.ProvideToken(context.Background())
	if err != nil {
		return nil, err
	}

	var groups []kc.GroupRepresentation
	groups, err = c.keycloakClient.GetGroups(accessToken, realmConf.Realm)
	if err != nil {
		return nil, err
	}

	var res []string
	for _, group := range groups {
		if validation.IsStringInSlice(realmConf.EndUserGroups, *group.Name) {
			res = append(res, *group.ID)
		}
	}

	if len(res) != len(realmConf.EndUserGroups) {
		return nil, errors.New("At least one group name could not be found")
	}
	return res, nil
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventsDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		internal.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}

func (c *component) RegisterUser(ctx context.Context, targetRealmName, customerRealmName string, user apiregister.UserRepresentation) (string, error) {
	if _, ok := c.realmConfigurations[targetRealmName]; !ok {
		return "", errorhandler.CreateNotFoundError("realm")
	}

	// Get Realm configuration from database
	var realmConf, err = c.configDBModule.GetConfiguration(ctx, customerRealmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm configuration from database", "err", err.Error())
		return "", err
	}

	// Get an OIDC token to be able to request Keycloak
	var accessToken string
	accessToken, err = c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return "", err
	}

	// Registering should be disallowed if an enabled user already exists with the same email
	var kcUser *kc.UserRepresentation
	kcUser, err = c.checkExistingUser(ctx, accessToken, targetRealmName, user)
	if err != nil {
		return "", err
	}

	var username, userID string
	userID, username, err = c.storeUser(ctx, accessToken, targetRealmName, customerRealmName, user, kcUser, realmConf)

	if err != nil {
		return "", err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "REGISTER_USER", database.CtEventRealmName, targetRealmName, database.CtEventUserID, userID, database.CtEventUsername, username)

	return username, nil
}

func (c *component) storeUser(ctx context.Context, accessToken string, targetRealmName, customerRealmName string, user apiregister.UserRepresentation, existingKcUser *kc.UserRepresentation, realmConf configuration.RealmConfiguration) (string, string, error) {
	authToken, err := c.generateAuthToken()

	var userID string
	var kcUser = user.ConvertToKeycloak()
	kcUser.SetAttributeString(constants.AttrbTrustIDAuthToken, authToken.ToJSON())

	if existingKcUser == nil {
		userID, err = c.createKeycloakUser(ctx, accessToken, targetRealmName, &kcUser)
		if err != nil {
			return "", "", err
		}
	} else {
		var realmConf = c.realmConfigurations[targetRealmName]
		userID = *existingKcUser.ID
		kcUser.ID = existingKcUser.ID
		kcUser.Username = existingKcUser.Username
		kcUser.Groups = &realmConf.endUserGroupIDs

		err = c.keycloakClient.UpdateUser(accessToken, targetRealmName, userID, kcUser)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
			return "", "", err
		}
	}

	// Store user in database
	err = c.usersDBModule.StoreOrUpdateUserDetails(ctx, targetRealmName, dto.DBUser{
		UserID:               &userID,
		BirthLocation:        user.BirthLocation,
		IDDocumentType:       user.IDDocumentType,
		IDDocumentNumber:     user.IDDocumentNumber,
		IDDocumentExpiration: user.IDDocumentExpiration,
	})
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store user details in database", "err", err.Error())
		return "", "", err
	}

	// Send execute actions email
	if err = c.sendExecuteActionsEmail(ctx, accessToken, targetRealmName, authToken, &kcUser, customerRealmName, userID, realmConf); err != nil {
		return "", "", err
	}

	return userID, *kcUser.Username, nil
}

func (c *component) createKeycloakUser(ctx context.Context, accessToken, targetRealmName string, kcUser *kc.UserRepresentation) (string, error) {
	var chars = []rune("0123456789")
	var userID string
	var err error

	for i := 0; i < 10; i++ {
		var groups = c.realmConfigurations[targetRealmName].endUserGroupIDs
		var username = c.generateUsername(chars, 8)
		kcUser.Username = &username
		kcUser.Groups = &groups

		userID, err = c.keycloakClient.CreateUser(accessToken, targetRealmName, targetRealmName, *kcUser)

		// Create success: just have to get the userID and exit this loop
		if err == nil {
			var re = regexp.MustCompile(`(^.*/users/)`)
			userID = re.ReplaceAllString(userID, "")
			break
		}
		userID = ""
		switch e := err.(type) {
		case errorhandler.Error:
			if e.Status == http.StatusConflict && e.Message == "keycloak.existing.username" {
				// Username already exists
				continue
			}
		}
		c.logger.Warn(ctx, "msg", "Failed to create user through Keycloak API", "err", err.Error())
		return "", err
	}
	if userID == "" {
		c.logger.Warn(ctx, "msg", "Can't generate unused username after multiple attempts")
		return "", errorhandler.CreateInternalServerError("username.generation")
	}
	return userID, nil
}

func (c *component) sendExecuteActionsEmail(ctx context.Context, accessToken string, targetRealmName string, authToken TrustIDAuthToken, kcUser *kc.UserRepresentation,
	customerRealmName, userID string, realmConf configuration.RealmConfiguration) error {

	redirectURL, err := url.Parse(c.keycloakURL + "/auth/realms/" + targetRealmName + "/protocol/openid-connect/auth")
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't parse keycloak URL", "err", err.Error())
		return errorhandler.CreateInternalServerError("url")
	}
	var parameters = url.Values{}
	var customerRealmConf = c.realmConfigurations[targetRealmName]
	parameters.Add("client_id", customerRealmConf.EnduserClientID)
	parameters.Add("scope", "openid")
	parameters.Add("response_type", "code")
	parameters.Add("trustid_auth_token", authToken.Token)

	if customerRealmConf.SsePublicURL != "" {
		parameters.Add("redirect_uri", customerRealmConf.SsePublicURL+"/"+targetRealmName+"/confirmation/"+customerRealmName)
		parameters.Add("login_hint", *kcUser.Username)
	}

	redirectURL.RawQuery = parameters.Encode()

	if realmConf.RegisterExecuteActions != nil && len(*realmConf.RegisterExecuteActions) > 0 {
		err = c.keycloakClient.ExecuteActionsEmail(accessToken, targetRealmName, userID,
			*realmConf.RegisterExecuteActions, "client_id", customerRealmConf.EnduserClientID, "redirect_uri", redirectURL.String())
		if err != nil {
			c.logger.Warn(ctx, "msg", "ExecuteActionsEmail failed", "err", err.Error())
			return err
		}
	}
	return nil
}

// Check if a user already exists in Keycloak... If such a user exists in database, he can register himself only if the existing user is not yet enabled
func (c *component) checkExistingUser(ctx context.Context, accessToken, targetRealmName string, user apiregister.UserRepresentation) (*kc.UserRepresentation, error) {
	// Search user by email
	var kcUsers, err = c.keycloakClient.GetUsers(accessToken, targetRealmName, targetRealmName, "email", *user.Email)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user from keycloak", "err", err.Error())
		return nil, errorhandler.CreateInternalServerError("keycloak")
	}
	if kcUsers.Count == nil || *kcUsers.Count == 0 {
		// New user: go on registering
		return nil, nil
	}

	var kcUser kc.UserRepresentation = kcUsers.Users[0]
	keycloakb.ConvertLegacyAttribute(&kcUser)
	if kcUser.EmailVerified == nil || *kcUser.EmailVerified {
		c.logger.Warn(ctx, "msg", "Attempt to register a user with email of an already validated user")
		// Should not leak that email is already in use
		return nil, errorhandler.CreateBadRequestError(errorhandler.MsgErrInvalidParam + ".user_emailAddress")
	}

	// Free to go on processing this user creation
	return &kcUser, nil
}

func (c *component) GetConfiguration(ctx context.Context, realmName string) (apiregister.ConfigurationRepresentation, error) {
	// Get Realm configuration from database
	var realmConf, realmAdminConf, err = c.configDBModule.GetConfigurations(ctx, realmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm configuration from database", "err", err.Error())
		return apiregister.ConfigurationRepresentation{}, err
	}

	return apiregister.ConfigurationRepresentation{
		RedirectCancelledRegistrationURL: realmConf.RedirectCancelledRegistrationURL,
		Mode:                             realmAdminConf.Mode,
	}, nil
}

func (c *component) generateUsername(chars []rune, length int) string {
	var b strings.Builder

	for j := 0; j < length; j++ {
		nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		index := int(nBig.Int64())
		b.WriteRune(chars[index])
	}
	return b.String()
}

func (c *component) generateAuthToken() (TrustIDAuthToken, error) {
	var bToken = make([]byte, 32)
	_, err := rand.Read(bToken)
	if err != nil {
		return TrustIDAuthToken{}, err
	}

	return TrustIDAuthToken{
		Token:     b64.StdEncoding.EncodeToString(bToken),
		CreatedAt: time.Now().Unix(),
	}, nil
}
