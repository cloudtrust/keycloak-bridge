package account

import (
	"context"
	"encoding/json"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/security"

	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
)

// Creates constants for API method names
const (
	UpdatePassword            = "UpdatePassword"
	GetCredentials            = "GetCredentials"
	GetCredentialRegistrators = "GetCredentialRegistrators"
	UpdateLabelCredential     = "UpdateLabelCredential"
	DeleteCredential          = "DeleteCredential"
	MoveCredential            = "MoveCredential"
	GetAccount                = "GetAccount"
	UpdateAccount             = "UpdateAccount"
	DeleteAccount             = "DeleteAccount"
	GetConfiguration          = "GetConfiguration"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	logger         log.Logger
	configDBModule ConfigurationDBModule
	next           Component
}

// MakeAuthorizationAccountComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationAccountComponentMW(logger log.Logger, configDBModule ConfigurationDBModule) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			logger:         logger,
			configDBModule: configDBModule,
			next:           next,
		}
	}
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	var action = UpdatePassword
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	var config = dto.RealmConfiguration{}
	var err error

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			"currentRealm": currentRealm,
		})
		c.logger.Error("Error", "Configuration not found", "infos", string(infos))
		return err
	}

	if !*config.APISelfPasswordChangeEnabled {
		infos, _ := json.Marshal(map[string]string{
			"Action":       action,
			"currentRealm": currentRealm,
		})
		c.logger.Debug("ForbiddenError", "Password change disabled", "infos", string(infos))
		return security.ForbiddenError{}
	}

	return c.next.UpdatePassword(ctx, currentPassword, newPassword, confirmPassword)
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) GetCredentials(ctx context.Context) ([]api.CredentialRepresentation, error) {
	// No restriction for this call
	return c.next.GetCredentials(ctx)
}

func (c *authorizationComponentMW) GetCredentialRegistrators(ctx context.Context) ([]string, error) {
	// No restriction for this call
	return c.next.GetCredentialRegistrators(ctx)
}

func (c *authorizationComponentMW) UpdateLabelCredential(ctx context.Context, credentialID string, label string) error {
	// No restriction for this call
	return c.next.UpdateLabelCredential(ctx, credentialID, label)
}

func (c *authorizationComponentMW) MoveCredential(ctx context.Context, credentialID string, previousCredentialID string) error {
	// No restriction for this call
	return c.next.MoveCredential(ctx, credentialID, previousCredentialID)
}

func (c *authorizationComponentMW) DeleteCredential(ctx context.Context, credentialID string) error {
	var action = DeleteCredential
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	var config = dto.RealmConfiguration{}
	var err error

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			"currentRealm": currentRealm,
		})
		c.logger.Error("Error", "Configuration not found", "infos", string(infos))
		return err
	}

	if !*config.APISelfAuthenticatorDeletionEnabled {
		infos, _ := json.Marshal(map[string]string{
			"Action":       action,
			"currentRealm": currentRealm,
		})
		c.logger.Debug("ForbiddenError", "Authenticator deletion disabled", "infos", string(infos))
		return security.ForbiddenError{}
	}

	return c.next.DeleteCredential(ctx, credentialID)
}

func (c *authorizationComponentMW) GetAccount(ctx context.Context) (api.AccountRepresentation, error) {
	// No restriction for this call
	return c.next.GetAccount(ctx)
}

func (c *authorizationComponentMW) UpdateAccount(ctx context.Context, account api.AccountRepresentation) error {
	var action = UpdateAccount
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	var config = dto.RealmConfiguration{}
	var err error

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			"currentRealm": currentRealm,
		})
		c.logger.Error("Error", "Configuration not found", "infos", string(infos))
		return err
	}

	if !*config.APISelfMailEditionEnabled {
		infos, _ := json.Marshal(map[string]string{
			"Action":       action,
			"currentRealm": currentRealm,
		})
		c.logger.Debug("ForbiddenError", "Mail edition disabled", "infos", string(infos))
		return security.ForbiddenError{}
	}

	return c.next.UpdateAccount(ctx, account)
}

func (c *authorizationComponentMW) DeleteAccount(ctx context.Context) error {
	var action = DeleteAccount
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	var err error
	var config = dto.RealmConfiguration{}

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			"currentRealm": currentRealm,
		})
		c.logger.Error("Error", "Configuration not found", "infos", string(infos))
		return err
	}

	if !*config.APISelfDeleteAccountEnabled {
		infos, _ := json.Marshal(map[string]string{
			"Action":       action,
			"currentRealm": currentRealm,
		})
		c.logger.Debug("ForbiddenError", "Account deletion disabled", "infos", string(infos))
		return security.ForbiddenError{}
	}
	return c.next.DeleteAccount(ctx)
}

func (c *authorizationComponentMW) GetConfiguration(ctx context.Context) (api.Configuration, error) {
	//No restriction for this call
	return c.next.GetConfiguration(ctx)
}
