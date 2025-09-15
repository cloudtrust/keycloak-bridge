package communications

import (
	"context"

	cerrors "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/communications"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
)

// KeycloakCommunicationsClient interface exposes methods we need to call to send requests to Keycloak communications API
type KeycloakCommunicationsClient interface {
	SendEmail(accessToken string, reqRealmName string, realmName string, emailRep kc.EmailRepresentation) error
	SendEmailToUser(accessToken string, reqRealmName string, realmName string, userID string, emailRep kc.EmailRepresentation) error
	SendSMS(accessToken string, realmName string, smsRep kc.SMSRepresentation) error
}

// Component interface exposes methods used by the bridge API
type Component interface {
	SendEmailToUser(ctx context.Context, realmName string, userID string, emailRep api.EmailRepresentation) error
	SendEmail(ctx context.Context, realmName string, emailRep api.EmailRepresentation) error
	SendSMS(ctx context.Context, realmName string, smsRep api.SMSRepresentation) error
}

type component struct {
	keycloakCommunicationsClient KeycloakCommunicationsClient
	tokenProvider                toolbox.OidcTokenProvider
	logger                       internal.Logger
}

// NewComponent returns the communications component.
func NewComponent(keycloakCommunicationsClient KeycloakCommunicationsClient, tokenProvider toolbox.OidcTokenProvider, logger internal.Logger) Component {
	return &component{
		keycloakCommunicationsClient: keycloakCommunicationsClient,
		tokenProvider:                tokenProvider,
		logger:                       logger,
	}
}

func (c *component) SendEmail(ctx context.Context, realmName string, emailRep api.EmailRepresentation) error {
	var accessToken string
	{
		var err error
		accessToken, err = c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
		if err != nil {
			c.logger.Error(ctx, "msg", "Can't get access token for technical user", "err", err.Error())
			return cerrors.CreateInternalServerError("token")
		}
	}

	var kcEmailRep = api.ExportEmailToKeycloak(&emailRep)
	err := c.keycloakCommunicationsClient.SendEmail(accessToken, realmName, realmName, *kcEmailRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}

func (c *component) SendEmailToUser(ctx context.Context, realmName string, userID string, emailRep api.EmailRepresentation) error {
	var accessToken string
	{
		var err error
		accessToken, err = c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
		if err != nil {
			c.logger.Error(ctx, "msg", "Can't get access token for technical user", "err", err.Error())
			return cerrors.CreateInternalServerError("token")
		}
	}

	var kcEmailRep = api.ExportEmailToKeycloak(&emailRep)
	err := c.keycloakCommunicationsClient.SendEmailToUser(accessToken, realmName, realmName, userID, *kcEmailRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}

func (c *component) SendSMS(ctx context.Context, realmName string, smsRep api.SMSRepresentation) error {
	var accessToken string
	{
		var err error
		accessToken, err = c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
		if err != nil {
			c.logger.Error(ctx, "msg", "Can't get access token for technical user", "err", err.Error())
			return cerrors.CreateInternalServerError("token")
		}
	}

	var kcSmsRep = api.ExportSMSToKeycloak(&smsRep)
	err := c.keycloakCommunicationsClient.SendSMS(accessToken, realmName, *kcSmsRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}
