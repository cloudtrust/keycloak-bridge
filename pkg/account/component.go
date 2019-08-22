package account

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	commonhttp "github.com/cloudtrust/common-service/http"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakAccountClient interface exposes methods we need to call to send requests to Keycloak API of Account
type KeycloakAccountClient interface {
	UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword string) (string, error)
	UpdateAccount(accessToken, realm string, user kc.UserRepresentation) error
	GetAccount(accessToken, realm string) (kc.UserRepresentation, error)
}

// Component interface exposes methods used by the bridge API
type Component interface {
	UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error
	GetAccount(ctx context.Context) (api.AccountRepresentation, error)
	UpdateAccount(context.Context, api.AccountRepresentation) error
}

// Component is the management component.
type component struct {
	keycloakClient KeycloakClient
	eventDBModule  database.EventsDBModule
	logger         internal.Logger
}

// NewComponent returns the self-service component.
func NewComponent(keycloakClient KeycloakClient, eventDBModule database.EventsDBModule, logger internal.Logger) Component {
	return &component{
		keycloakClient: keycloakClient,
		eventDBModule:  eventDBModule,
		logger:         logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) error {
	return c.eventDBModule.ReportEvent(ctx, apiCall, "self-service", values...)
}

func (c *component) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	if currentPassword == newPassword || newPassword != confirmPassword {
		return commonhttp.Error{
			Status:  http.StatusBadRequest,
			Message: ComponentName + "." + "invalidValues",
		}
	}

	_, err := c.keycloakAccountClient.UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword)

	//store the API call into the DB
	err = c.reportEvent(ctx, "PASSWORD_RESET", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)
	if err != nil {
		//store in the logs also the event that failed to be stored in the DB
		m := map[string]interface{}{"event_name": "PASSWORD_RESET", database.CtEventRealmName: realm, database.CtEventUserID: userID, database.CtEventUsername: username}
		eventJSON, errMarshal := json.Marshal(m)
		if errMarshal == nil {
			c.logger.Error("err", err.Error(), "event", string(eventJSON))
		} else {
			c.logger.Error("err", err.Error())
		}

	}

	return updateError
}

func (c *component) GetAccount(ctx context.Context) (api.AccountRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)

	var userRep api.AccountRepresentation
	userKc, err := c.keycloakClient.GetAccount(accessToken, realm)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return userRep, err
	}

	userRep = api.ConvertToAPIAccount(userKc)

	return userRep, nil
}

func (c *component) UpdateAccount(ctx context.Context, user api.AccountRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)
	var userRep kc.UserRepresentation

	// get the "old" user representation
	oldUserKc, err := c.keycloakClient.GetAccount(accessToken, realm)
	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	var emailVerified, phoneNumberVerified *bool

	// when the email changes, set the EmailVerified to false
	if user.Email != nil && oldUserKc.Email != nil && *oldUserKc.Email != *user.Email {
		var verified = false
		emailVerified = &verified
	}

	// when the phone number changes, set the PhoneNumberVerified to false
	if user.PhoneNumber != nil {
		if oldUserKc.Attributes != nil {
			var m = *oldUserKc.Attributes
			if _, ok := m["phoneNumber"]; !ok || m["phoneNumber"][0] != *user.PhoneNumber {
				var verified = false
				phoneNumberVerified = &verified
			}
		} else { // the user has no attributes until now, i.e. he has not set yet his phone number
			var verified = false
			phoneNumberVerified = &verified
		}
	}

	userRep = api.ConvertToKCUser(user)

	if emailVerified != nil {
		userRep.EmailVerified = emailVerified
	}

	// Merge the attributes coming from the old user representation and the updated user representation in order not to lose anything
	var mergedAttributes = make(map[string][]string)

	//Populate with the old attributes
	if oldUserKc.Attributes != nil {
		for key, attribute := range *oldUserKc.Attributes {
			mergedAttributes[key] = attribute
		}
	}

	if user.PhoneNumber != nil {
		mergedAttributes["phoneNumber"] = []string{*user.PhoneNumber}
	}

	if phoneNumberVerified != nil {
		mergedAttributes["phoneNumberVerified"] = []string{strconv.FormatBool(*phoneNumberVerified)}
	}

	userRep.Attributes = &mergedAttributes

	err = c.keycloakClient.UpdateAccount(accessToken, realm, userRep)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	//store the API call into the DB
	_ = c.reportEvent(ctx, "UPDATE_ACCOUNT", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)

	return nil
}
