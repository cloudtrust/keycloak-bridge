package statistics

import (
	"context"

	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// Component is the interface of the events component.
type Component interface {
	GetStatistics(context.Context, map[string]string) (api.StatisticsRepresentation, error)
}

type component struct {
	db keycloakb.EventsDBModule
}

// NewComponent returns a component
func NewComponent(db keycloakb.EventsDBModule) Component {
	return &component{
		db: db,
	}
}

// Grabs statistics
func (ec *component) GetStatistics(ctx context.Context, m map[string]string) (api.StatisticsRepresentation, error) {
	var res api.StatisticsRepresentation
	var err error
	var realmName = m["realm"]

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
