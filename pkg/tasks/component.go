package tasks

import (
	"context"
	"database/sql"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-client"
)

// Component interface exposes methods used by the bridge API
type Component interface {
	CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx context.Context) error
}

// KeycloakClient interface
type KeycloakClient interface {
	DeleteUser(accessToken string, realmName, userID string) error
	GetExpiredTermsOfUseAcceptance(accessToken string) ([]keycloak.DeletableUserRepresentation, error)
}

// UsersDetailsDBModule is the interface from the users module
type UsersDetailsDBModule interface {
	DeleteUserDetails(ctx context.Context, realm string, userID string) error
}

type component struct {
	keycloakClient KeycloakClient
	usersDBModule  UsersDetailsDBModule
	eventDBModule  database.EventsDBModule
	logger         log.Logger
}

// NewComponent returns a component
func NewComponent(keycloakClient KeycloakClient, usersDBModule UsersDetailsDBModule, eventDBModule database.EventsDBModule,
	logger log.Logger) Component {
	return &component{
		keycloakClient: keycloakClient,
		usersDBModule:  usersDBModule,
		eventDBModule:  eventDBModule,

		logger: logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventDBModule.ReportEvent(ctx, apiCall, "scheduled-tasks", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		keycloakb.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}

func (c *component) CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx context.Context) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var users, err = c.keycloakClient.GetExpiredTermsOfUseAcceptance(accessToken)

	if err != nil {
		c.logger.Info(ctx, "msg", "Can't execute keycloak method GetExpiredTermsOfUseAcceptance")
		return err
	}

	// Best effort: in case of error go on trying to remove other users
	var finalError error

	for _, user := range users {
		err = c.usersDBModule.DeleteUserDetails(ctx, user.RealmName, user.UserID)
		if err != nil && err != sql.ErrNoRows {
			c.logger.Warn(ctx, "msg", "Could not delete database user", "realm", user.RealmName, "usr", user.UserID, "err", err.Error())
			finalError = err
		} else {
			err = c.keycloakClient.DeleteUser(accessToken, user.RealmName, user.UserID)
			if err != nil {
				c.logger.Warn(ctx, "msg", "Could not delete keycloak user", "realm", user.RealmName, "usr", user.UserID, "err", err.Error())
				finalError = err
			} else {
				c.logger.Info(ctx, "msg", "Removed user without terms and conditions acceptance", "realm", user.RealmName, "usr", user.UserID)
				//store the API call into the DB
				c.reportEvent(ctx, "API_ACCOUNT_DELETION", database.CtEventRealmName, user.RealmName, database.CtEventUserID, user.UserID)
			}
		}
	}

	return finalError
}
