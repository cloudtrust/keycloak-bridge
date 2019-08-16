package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// Component is the interface of the events component.
type Component interface {
	GetStatistics(context.Context, string) (api.StatisticsRepresentation, error)
	GetMigrationReport(context.Context, string) (map[string]bool, error)
}

type KeycloakClient interface {
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
}

type component struct {
	db             keycloakb.EventsDBModule
	keycloakClient KeycloakClient
	logger         log.Logger
}

// NewComponent returns a component
func NewComponent(db keycloakb.EventsDBModule, keycloakClient KeycloakClient, logger log.Logger) Component {
	return &component{
		db:             db,
		keycloakClient: keycloakClient,
		logger:         logger,
	}
}

// Grabs statistics
func (ec *component) GetStatistics(ctx context.Context, realmName string) (api.StatisticsRepresentation, error) {
	var res api.StatisticsRepresentation
	var err error

	res.LastConnection, err = ec.db.GetLastConnection(ctx, realmName)

	if err == nil {
		res.TotalConnections.LastTwelveHours, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "12 HOUR")
	}
	if err == nil {
		res.TotalConnections.LastDay, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 DAY")
	}
	if err == nil {
		res.TotalConnections.LastWeek, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 WEEK")
	}
	if err == nil {
		res.TotalConnections.LastMonth, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 MONTH")
	}
	if err == nil {
		res.TotalConnections.LastYear, err = ec.db.GetTotalConnectionsCount(ctx, realmName, "1 YEAR")
	}

	return res, err
}

// Compute Migration Report
func (ec *component) GetMigrationReport(ctx context.Context, realmName string) (map[string]bool, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	var paramKV = []string{}
	paramKV = append(paramKV, "max", "0") //All

	usersKc, err := ec.keycloakClient.GetUsers(accessToken, ctxRealm, realmName, paramKV...)

	if err != nil {
		ec.logger.Warn("err", err.Error())
		return map[string]bool{}, err
	}

	var migratedUsers = map[string]bool{}

	for _, user := range usersKc.Users {
		migratedUsers[*user.Username] = isMigrated(user)
	}

	return migratedUsers, nil
}

func isMigrated(user kc.UserRepresentation) bool {
	if user.Attributes == nil {
		return false
	}

	var attributes = *(user.Attributes)

	if len(attributes["migrated"]) != 0 && attributes["migrated"][0] == "true" {
		return true
	}

	return false
}
