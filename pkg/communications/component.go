package communications

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	api "github.com/cloudtrust/keycloak-bridge/api/communications"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
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
	logger                       internal.Logger
}

// NewComponent returns the communications component.
func NewComponent(keycloakCommunicationsClient KeycloakCommunicationsClient, logger internal.Logger) Component {
	return &component{
		keycloakCommunicationsClient: keycloakCommunicationsClient,
		logger:                       logger,
	}
}

func (c *component) SendEmail(ctx context.Context, realmName string, emailRep api.EmailRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	var kcEmailRep = api.ExportEmailToKeycloak(&emailRep)
	err := c.keycloakCommunicationsClient.SendEmail(accessToken, ctxRealm, realmName, *kcEmailRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}

func (c *component) SendEmailToUser(ctx context.Context, realmName string, userID string, emailRep api.EmailRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	var kcEmailRep = api.ExportEmailToKeycloak(&emailRep)
	err := c.keycloakCommunicationsClient.SendEmailToUser(accessToken, ctxRealm, realmName, userID, *kcEmailRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}

func (c *component) SendSMS(ctx context.Context, realmName string, smsRep api.SMSRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var kcSmsRep = api.ExportSMSToKeycloak(&smsRep)
	err := c.keycloakCommunicationsClient.SendSMS(accessToken, realmName, *kcSmsRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}
