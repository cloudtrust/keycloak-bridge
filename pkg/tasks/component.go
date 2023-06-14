package tasks

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/events"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-client/v2"
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

// EventsReporterModule is the interface of the audit events module
type EventsReporterModule interface {
	ReportEvent(ctx context.Context, event events.Event)
}

type component struct {
	keycloakClient      KeycloakClient
	eventReporterModule EventsReporterModule
	logger              log.Logger
	originEvent         string
}

// NewComponent returns a component
func NewComponent(keycloakClient KeycloakClient, eventReporterModule EventsReporterModule,
	logger log.Logger) Component {
	return &component{
		keycloakClient:      keycloakClient,
		eventReporterModule: eventReporterModule,
		logger:              logger,
		originEvent:         "scheduled-tasks",
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
		err = c.keycloakClient.DeleteUser(accessToken, user.RealmName, user.UserID)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Could not delete keycloak user", "realm", user.RealmName, "usr", user.UserID, "err", err.Error())
			finalError = err
		} else {
			c.logger.Info(ctx, "msg", "Removed user without terms and conditions acceptance", "realm", user.RealmName, "usr", user.UserID)
			//store the API call into the DB
			c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "API_ACCOUNT_DELETION", user.RealmName, user.UserID, user.Username, nil))
		}
	}

	return finalError
}
