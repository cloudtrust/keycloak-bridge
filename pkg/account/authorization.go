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
	GetLinkedAccounts         = "GetLinkedAccounts"
	DeleteLinkedAccount       = "DeleteLinkedAccount"

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

func (c *authorizationComponentMW) getRealmConfiguration(ctx context.Context) (configuration.RealmConfiguration, error) {
	currentRealm := ctx.Value(cs.CtContextRealm).(string)

	config, err := c.configDBModule.GetConfiguration(ctx, currentRealm)
	if err != nil {
		infos, _ := json.Marshal(map[string]string{
			infosCurrentRealm: currentRealm,
		})
		c.logger.Error(ctx, "err", "Configuration not found", "infos", string(infos))
	}

	return config, err
}

func (c *authorizationComponentMW) checkFlagEnabled(ctx context.Context, flagEnabled *bool, action string, disabledMessage string,
) error {
	currentRealm := ctx.Value(cs.CtContextRealm).(string)

	if !isEnabled(flagEnabled) {
		infos, _ := json.Marshal(map[string]string{
			infosAction:       action,
			infosCurrentRealm: currentRealm,
		})
		c.logger.Debug(ctx, "err", disabledMessage, "infos", string(infos))
		return security.ForbiddenError{}
	}
	return nil
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	if err := c.checkAPISelfPasswordChangeEnabled(ctx); err != nil {
		return err
	}

	return c.next.UpdatePassword(ctx, currentPassword, newPassword, confirmPassword)
}

func (c *authorizationComponentMW) checkAPISelfPasswordChangeEnabled(ctx context.Context) error {
	config, err := c.getRealmConfiguration(ctx)
	if err != nil {
		return err
	}

	return c.checkFlagEnabled(ctx, config.APISelfPasswordChangeEnabled, UpdatePassword, "Forbidden: password change disabled")
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
	if err := c.checkAPISelfAuthenticatorDeletionEnabled(ctx); err != nil {
		return err
	}

	return c.next.DeleteCredential(ctx, credentialID)
}

func (c *authorizationComponentMW) checkAPISelfAuthenticatorDeletionEnabled(ctx context.Context) error {
	config, err := c.getRealmConfiguration(ctx)
	if err != nil {
		return err
	}

	return c.checkFlagEnabled(ctx, config.APISelfAuthenticatorDeletionEnabled, DeleteCredential, "Forbidden: authenticator deletion disabled")
}

func (c *authorizationComponentMW) GetAccount(ctx context.Context) (api.AccountRepresentation, error) {
	// No restriction for this call
	return c.next.GetAccount(ctx)
}

func (c *authorizationComponentMW) UpdateAccount(ctx context.Context, account api.UpdatableAccountRepresentation) error {
	if err := c.checkAPISelfAccountEditingEnabled(ctx); err != nil {
		return err
	}

	return c.next.UpdateAccount(ctx, account)
}

func (c *authorizationComponentMW) checkAPISelfAccountEditingEnabled(ctx context.Context) error {
	config, err := c.getRealmConfiguration(ctx)
	if err != nil {
		return err
	}

	return c.checkFlagEnabled(ctx, config.APISelfAccountEditingEnabled, UpdateAccount, "Forbidden: account edition disabled")
}

func (c *authorizationComponentMW) DeleteAccount(ctx context.Context) error {
	if err := c.checkAPISelfAccountDeletionEnabled(ctx); err != nil {
		return err
	}

	return c.next.DeleteAccount(ctx)
}

func (c *authorizationComponentMW) checkAPISelfAccountDeletionEnabled(ctx context.Context) error {
	config, err := c.getRealmConfiguration(ctx)
	if err != nil {
		return err
	}

	return c.checkFlagEnabled(ctx, config.APISelfAccountDeletionEnabled, DeleteAccount, "Forbidden: account deletion disabled")
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

func (c *authorizationComponentMW) CancelEmailChange(ctx context.Context) error {
	// No restriction for this call
	return c.next.CancelEmailChange(ctx)
}

func (c *authorizationComponentMW) CancelPhoneNumberChange(ctx context.Context) error {
	// No restriction for this call
	return c.next.CancelPhoneNumberChange(ctx)
}

func isEnabled(booleanPtr *bool) bool {
	return booleanPtr != nil && *booleanPtr
}

func (c *authorizationComponentMW) GetLinkedAccounts(ctx context.Context) ([]api.LinkedAccountRepresentation, error) {
	if err := c.checkAPISelfIDPLinksManagementEnabled(ctx, GetLinkedAccounts); err != nil {
		return []api.LinkedAccountRepresentation{}, err
	}

	return c.next.GetLinkedAccounts(ctx)
}

func (c *authorizationComponentMW) DeleteLinkedAccount(ctx context.Context, providerAlias string) error {
	if err := c.checkAPISelfIDPLinksManagementEnabled(ctx, DeleteLinkedAccount); err != nil {
		return err
	}

	return c.next.DeleteLinkedAccount(ctx, providerAlias)
}

func (c *authorizationComponentMW) checkAPISelfIDPLinksManagementEnabled(ctx context.Context, action string) error {
	config, err := c.getRealmConfiguration(ctx)
	if err != nil {
		return err
	}

	return c.checkFlagEnabled(ctx, config.APISelfIDPLinksManagementEnabled, action, "Forbidden: linked accounts management disabled")
}
