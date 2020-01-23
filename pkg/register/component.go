package register

import (
	"context"
	"crypto/rand"
	b64 "encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cloudtrust/keycloak-client"

	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation) (string, error)
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	ExecuteActionsEmail(accessToken string, realmName string, userID string, actions []string, paramKV ...string) error
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	GetConfiguration(context.Context, string) (dto.RealmConfiguration, error)
}

// Component is the register component interface.
type Component interface {
	RegisterUser(ctx context.Context, clientRealmName string, user apiregister.UserRepresentation) (string, error)
	GetConfiguration(ctx context.Context, realmName string) (apiregister.ConfigurationRepresentation, error)
}

// Component is the management component.
type component struct {
	keycloakURL             string
	realm                   string
	ssePublicURL            string
	registerEnduserClientID string
	keycloakClient          KeycloakClient
	tokenProvider           keycloak.OidcTokenProvider
	usersDBModule           keycloakb.UsersDBModule
	configDBModule          ConfigurationDBModule
	eventsDBModule          database.EventsDBModule
	logger                  internal.Logger
}

// NewComponent returns the management component.
func NewComponent(keycloakURL string, realm string, ssePublicURL string, registerEnduserClientID string, keycloakClient KeycloakClient,
	tokenProvider keycloak.OidcTokenProvider, usersDBModule keycloakb.UsersDBModule,
	configDBModule ConfigurationDBModule, eventsDBModule database.EventsDBModule, logger internal.Logger) Component {
	return &component{
		keycloakURL:             keycloakURL,
		realm:                   realm,
		ssePublicURL:            ssePublicURL,
		registerEnduserClientID: registerEnduserClientID,
		keycloakClient:          keycloakClient,
		tokenProvider:           tokenProvider,
		usersDBModule:           usersDBModule,
		configDBModule:          configDBModule,
		eventsDBModule:          eventsDBModule,
		logger:                  logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventsDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		internal.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}

func (c *component) RegisterUser(ctx context.Context, clientRealmName string, user apiregister.UserRepresentation) (string, error) {
	// Validate input request
	var err = user.Validate()
	if err != nil {
		c.logger.Info(ctx, "err", err.Error())
		return "", err
	}

	// Get Realm configuration from database
	var realmConf dto.RealmConfiguration
	realmConf, err = c.configDBModule.GetConfiguration(ctx, clientRealmName)
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
	kcUser, err = c.checkExistingUser(ctx, accessToken, user)
	if err != nil {
		return "", err
	}

	var username, userID string
	userID, username, err = c.storeUser(ctx, accessToken, user, kcUser, realmConf)

	if err != nil {
		return "", err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "REGISTER_USER", database.CtEventRealmName, c.realm, database.CtEventUserID, userID, database.CtEventUsername, username)

	return "", nil
}

func (c *component) storeUser(ctx context.Context, accessToken string, user apiregister.UserRepresentation, existingKcUser *kc.UserRepresentation, realmConf dto.RealmConfiguration) (string, string, error) {
	authToken, err := c.generateAuthToken()

	var userID string
	var kcUser = user.ConvertToKeycloak()
	(*kcUser.Attributes)["trustIDAuthToken"] = []string{authToken}

	if existingKcUser == nil {
		var chars = []rune("0123456789")
		for i := 0; i < 10; i++ {
			var username = c.generateUsername(chars, 8)
			kcUser.Username = &username

			userID, err = c.keycloakClient.CreateUser(accessToken, c.realm, c.realm, kcUser)

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
			return "", "", err
		}
		if userID == "" {
			c.logger.Warn(ctx, "msg", "Can't generate unused username after multiple attempts")
			return "", "", errorhandler.CreateInternalServerError("username.generation")
		}
	} else {
		userID = *existingKcUser.Id
		kcUser.Id = existingKcUser.Id
		kcUser.Username = existingKcUser.Username

		err = c.keycloakClient.UpdateUser(accessToken, c.realm, userID, kcUser)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
			return "", "", err
		}
	}

	// Store user in database
	err = c.usersDBModule.StoreOrUpdateUser(ctx, c.realm, dto.DBUser{
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
	redirectURL, err := url.Parse(c.keycloakURL + "/auth/realms/" + c.realm + "/protocol/openid-connect/auth")
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't parse keycloak URL", "err", err.Error())
		return "", "", errorhandler.CreateInternalServerError("url")
	}
	var parameters = url.Values{}
	parameters.Add("client_id", c.registerEnduserClientID)
	parameters.Add("scope", "openid")
	parameters.Add("response_type", "code")
	parameters.Add("trustid_auth_token", authToken)

	if c.ssePublicURL != "" {
		parameters.Add("redirect_uri", c.ssePublicURL+"/"+c.realm+"/confirmation/"+c.realm)
		parameters.Add("login_hint", *kcUser.Username)
	}

	redirectURL.RawQuery = parameters.Encode()

	if realmConf.RegisterExecuteActions != nil && len(*realmConf.RegisterExecuteActions) > 0 {
		err = c.keycloakClient.ExecuteActionsEmail(accessToken, c.realm, userID,
			*realmConf.RegisterExecuteActions, "client_id", c.registerEnduserClientID, "redirect_uri", redirectURL.String())
		if err != nil {
			c.logger.Warn(ctx, "msg", "ExecuteActionsEmail failed", "err", err.Error())
			return "", "", err
		}
	}

	return userID, *kcUser.Username, nil
}

// Check if a user already exists in Keycloak... If such a user exists in database, he can register himself only if the existing user is not yet enabled
func (c *component) checkExistingUser(ctx context.Context, accessToken string, user apiregister.UserRepresentation) (*kc.UserRepresentation, error) {
	// Search user by email
	var kcUsers, err = c.keycloakClient.GetUsers(accessToken, c.realm, c.realm, "email", *user.EmailAddress)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user from db", "err", err.Error())
		return nil, errorhandler.CreateInternalServerError("database")
	}
	if kcUsers.Count == nil || *kcUsers.Count == 0 {
		// New user: go on registering
		return nil, nil
	}

	var kcUser kc.UserRepresentation = kcUsers.Users[0]
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
	var realmConf dto.RealmConfiguration
	realmConf, err := c.configDBModule.GetConfiguration(ctx, realmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm configuration from database", "err", err.Error())
		return apiregister.ConfigurationRepresentation{}, err
	}

	return apiregister.ConfigurationRepresentation{
		RedirectCancelledRegistrationURL: realmConf.RedirectCancelledRegistrationURL,
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

func (c *component) generateAuthToken() (string, error) {
	var bToken = make([]byte, 32)
	_, err := rand.Read(bToken)
	if err != nil {
		return "", err
	}

	token := b64.StdEncoding.EncodeToString(bToken)
	return token, nil
}
