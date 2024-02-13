package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// Component is the interface of the events component.
type Component interface {
	GetActions(context.Context) ([]api.ActionRepresentation, error)
	GetStatisticsIdentifications(context.Context, string) (api.IdentificationStatisticsRepresentation, error)
	GetStatisticsUsers(context.Context, string) (api.StatisticsUsersRepresentation, error)
	GetStatisticsAuthenticators(context.Context, string) (map[string]int64, error)
	GetMigrationReport(context.Context, string) (map[string]bool, error)
}

// KeycloakClient interface
type KeycloakClient interface {
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetStatisticsUsers(accessToken string, realmName string) (kc.StatisticsUsersRepresentation, error)
	GetStatisticsAuthenticators(accessToken string, realmName string) (map[string]int64, error)
}

// AccreditationsServiceClient interface
type AccreditationsServiceClient interface {
	GetIdentityChecksByNature(ctx context.Context, realm string) ([]accreditationsclient.NatureCheckCount, error)
}

type component struct {
	keycloakClient KeycloakClient
	accredsService AccreditationsServiceClient
	logger         log.Logger
}

// NewComponent returns a component
func NewComponent(keycloakClient KeycloakClient, accredsService AccreditationsServiceClient, logger log.Logger) Component {
	return &component{
		keycloakClient: keycloakClient,
		accredsService: accredsService,
		logger:         logger,
	}
}

// Get actions
func (ec *component) GetActions(ctx context.Context) ([]api.ActionRepresentation, error) {
	var apiActions = []api.ActionRepresentation{}

	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.StatisticAPI) {
		var name = action.Name
		var scope = string(action.Scope)

		apiActions = append(apiActions, api.ActionRepresentation{
			Name:  &name,
			Scope: &scope,
		})
	}

	return apiActions, nil
}

// Grabs identification statistics
func (ec *component) GetStatisticsIdentifications(ctx context.Context, realmName string) (api.IdentificationStatisticsRepresentation, error) {
	stats, err := ec.accredsService.GetIdentityChecksByNature(ctx, realmName)
	if err != nil {
		ec.logger.Warn(ctx, "msg", "Failed to retrieve identification statistics", "err", err.Error())
		return api.IdentificationStatisticsRepresentation{}, err
	}

	var res api.IdentificationStatisticsRepresentation
	for _, stat := range stats {
		switch *stat.Nature {
		case "BASIC_CHECK":
			res.BasicIdentifications = *stat.Count
		case "PHYSICAL_CHECK":
			res.PhysicalIdentifications = *stat.Count
		case "IDNOW_CHECK":
			res.VideoIdentifications = *stat.Count
		case "AUTO_IDENT_IDNOW_CHECK":
			res.AutoIdentifications = *stat.Count
		}
	}

	return res, nil
}

// GetStatisticsUsers gives statistics on the total number of users and on those that are inactive or disabled
func (ec *component) GetStatisticsUsers(ctx context.Context, realmName string) (api.StatisticsUsersRepresentation, error) {
	var err error
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	res, err := ec.keycloakClient.GetStatisticsUsers(accessToken, realmName)

	if err != nil {
		ec.logger.Warn(ctx, "err", err.Error())
		return api.StatisticsUsersRepresentation{}, err
	}
	return api.ConvertToAPIStatisticsUsers(res), nil
}

// GetStatisticsAuthenticators gives  statistics on the types of authenticators used by the users of a certain realm
func (ec *component) GetStatisticsAuthenticators(ctx context.Context, realmName string) (map[string]int64, error) {
	var err error
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	res, err := ec.keycloakClient.GetStatisticsAuthenticators(accessToken, realmName)

	if err != nil {
		ec.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}
	return res, nil
}

// Compute Migration Report
func (ec *component) GetMigrationReport(ctx context.Context, realmName string) (map[string]bool, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	var paramKV = []string{}
	paramKV = append(paramKV, prmQryMax, "0") //All

	usersKc, err := ec.keycloakClient.GetUsers(accessToken, ctxRealm, realmName, paramKV...)

	if err != nil {
		ec.logger.Warn(ctx, "err", err.Error())
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
