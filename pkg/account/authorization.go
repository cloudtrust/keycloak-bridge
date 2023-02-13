package account

import (
	"context"
	"encoding/json"

	"github.com/cloudtrust/common-service/v2/configuration"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/security"

	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
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

	infosAction       = "Action"
	infosCurrentRealm = "currentRealm"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	logger         log.Logger
	configDBModule keycloakb.ConfigurationDBModule
	next           Component
}

// MakeAuthorizationAccountComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationAccountComponentMW(logger log.Logger, configDBModule keycloakb.ConfigurationDBModule) func(Component) Component {
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

	var config = configuration.RealmConfiguration{}
	var err error

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			infosCurrentRealm: currentRealm,
		})
		c.logger.Error(ctx, "err", "Configuration not found", "infos", string(infos))
		return err
	}

	if !isEnabled(config.APISelfPasswordChangeEnabled) {
		infos, _ := json.Marshal(map[string]string{
			infosAction:       action,
			infosCurrentRealm: currentRealm,
		})
		c.logger.Debug(ctx, "err", "Forbidden: password change disabled", "infos", string(infos))
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

	var config = configuration.RealmConfiguration{}
	var err error

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			infosCurrentRealm: currentRealm,
		})
		c.logger.Error(ctx, "err", "Configuration not found", "infos", string(infos))
		return err
	}

	if !isEnabled(config.APISelfAuthenticatorDeletionEnabled) {
		infos, _ := json.Marshal(map[string]string{
			infosAction:       action,
			infosCurrentRealm: currentRealm,
		})
		c.logger.Debug(ctx, "err", "Forbidden: authenticator deletion disabled", "infos", string(infos))
		return security.ForbiddenError{}
	}

	return c.next.DeleteCredential(ctx, credentialID)
}

func (c *authorizationComponentMW) GetAccount(ctx context.Context) (api.AccountRepresentation, error) {
	// No restriction for this call
	return c.next.GetAccount(ctx)
}

func (c *authorizationComponentMW) UpdateAccount(ctx context.Context, account api.UpdatableAccountRepresentation) error {
	var action = UpdateAccount
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	var config = configuration.RealmConfiguration{}
	var err error

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			infosCurrentRealm: currentRealm,
		})
		c.logger.Error(ctx, "err", "Configuration not found", "infos", string(infos))
		return err
	}

	if !isEnabled(config.APISelfAccountEditingEnabled) {
		infos, _ := json.Marshal(map[string]string{
			infosAction:       action,
			infosCurrentRealm: currentRealm,
		})
		c.logger.Debug(ctx, "err", "Forbidden: account edition disabled", "infos", string(infos))
		return security.ForbiddenError{}
	}

	return c.next.UpdateAccount(ctx, account)
}

func (c *authorizationComponentMW) DeleteAccount(ctx context.Context) error {
	var action = DeleteAccount
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	var err error
	var config = configuration.RealmConfiguration{}

	if config, err = c.configDBModule.GetConfiguration(ctx, currentRealm); err != nil {
		infos, _ := json.Marshal(map[string]string{
			infosCurrentRealm: currentRealm,
		})
		c.logger.Error(ctx, "err", "Configuration not found", "infos", string(infos))
		return err
	}

	if !isEnabled(config.APISelfAccountDeletionEnabled) {
		infos, _ := json.Marshal(map[string]string{
			infosAction:       action,
			infosCurrentRealm: currentRealm,
		})
		c.logger.Debug(ctx, "err", "Forbidden: account deletion disabled", "infos", string(infos))
		return security.ForbiddenError{}
	}
	return c.next.DeleteAccount(ctx)
}

func (c *authorizationComponentMW) GetConfiguration(ctx context.Context, realmIDOverride string) (api.Configuration, error) {
	// No restriction for this call
	return c.next.GetConfiguration(ctx, realmIDOverride)
}

func (c *authorizationComponentMW) GetUserProfile(ctx context.Context) (apicommon.ProfileRepresentation, error) {
	// No restriction for this call
	return c.next.GetUserProfile(ctx)
}

func (c *authorizationComponentMW) SendVerifyEmail(ctx context.Context) error {
	// No restriction for this call
	return c.next.SendVerifyEmail(ctx)
}

func (c *authorizationComponentMW) SendVerifyPhoneNumber(ctx context.Context) error {
	// No restriction for this call
	return c.next.SendVerifyPhoneNumber(ctx)
}

func isEnabled(booleanPtr *bool) bool {
	return booleanPtr != nil && *booleanPtr
}
