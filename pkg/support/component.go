package support

import (
	"context"
	"net/http"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/support"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// Component interface exposes methods used by the bridge API
type Component interface {
	GetSupportInformation(ctx context.Context, email string) ([]api.EmailInfo, error)
}

// KeycloakClient interface
type KeycloakClient interface {
	GetSupportInfo(accessToken string, email string) ([]kc.EmailInfoRepresentation, error)
}

type component struct {
	keycloakClient KeycloakClient
	logger         log.Logger
}

// NewComponent returns a component
func NewComponent(keycloakClient KeycloakClient, logger log.Logger) Component {
	return &component{
		keycloakClient: keycloakClient,
		logger:         logger,
	}
}

func (c *component) GetSupportInformation(ctx context.Context, email string) ([]api.EmailInfo, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var res, err = c.keycloakClient.GetSupportInfo(accessToken, email)
	if err != nil {
		switch e := err.(type) {
		case kc.HTTPError:
			if e.HTTPStatus == http.StatusNotFound {
				return nil, errorhandler.CreateNotFoundError("email")
			}
		}
		c.logger.Info(ctx, "msg", "Can't get support information", "err", err.Error())
		return nil, err
	}
	return api.ConvertToEmailInfo(res), nil
}
