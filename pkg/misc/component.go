package misc

import (
	"context"
	"net/http"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/misc"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// Component interface exposes methods used by the bridge API
type Component interface {
	// Support
	GetSupportInformation(ctx context.Context, email string) ([]api.EmailInfo, error)
	// Circuit breaker management
	GetCircuitBreakerStatus(ctx context.Context, realm string) (api.CircuitBreakerStatus, error)
	OpenCircuitBreaker(ctx context.Context, realm string) error
	CloseCircuitBreaker(ctx context.Context, realm string) error
}

// KeycloakClient interface
type KeycloakClient interface {
	GetSupportInfo(accessToken string, email string) ([]kc.EmailInfoRepresentation, error)
	GetCircuitBreakerStatus(accessToken string, realmName string) (kc.CircuitBreakerRepresentation, error)
	OpenCircuitBreaker(accessToken string, realmName string) (kc.CircuitBreakerRepresentation, error)
	CloseCircuitBreaker(accessToken string, realmName string) (kc.CircuitBreakerRepresentation, error)
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

func (c *component) GetCircuitBreakerStatus(ctx context.Context, realm string) (api.CircuitBreakerStatus, error) {
	accessToken := ctx.Value(cs.CtContextAccessToken).(string)
	res, err := c.keycloakClient.GetCircuitBreakerStatus(accessToken, realm)
	if err != nil {
		return api.CircuitBreakerStatus{}, handleKeycloakError(err)
	}
	return api.ConvertToCircuitBreakerStatus(res), nil
}

func (c *component) OpenCircuitBreaker(ctx context.Context, realm string) error {
	accessToken := ctx.Value(cs.CtContextAccessToken).(string)
	_, err := c.keycloakClient.OpenCircuitBreaker(accessToken, realm)
	return handleKeycloakError(err)
}

func (c *component) CloseCircuitBreaker(ctx context.Context, realm string) error {
	accessToken := ctx.Value(cs.CtContextAccessToken).(string)
	_, err := c.keycloakClient.CloseCircuitBreaker(accessToken, realm)
	return handleKeycloakError(err)
}

func handleKeycloakError(err error) error {
	switch e := err.(type) {
	case kc.HTTPError: // Error remains internal... we can transfer all information
		return errorhandler.Error{
			Status:  e.HTTPStatus,
			Message: e.Message,
		}
	}
	return err
}
