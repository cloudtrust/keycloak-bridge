package communications

import (
	"context"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/communications"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// MakeAuthorizationCommunicationsComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationCommunicationsComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (c *authorizationComponentMW) SendEmail(ctx context.Context, realmName string, emailRep api.EmailRepresentation) error {
	var action = security.COMSendEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.SendEmail(ctx, realmName, emailRep)
}

func (c *authorizationComponentMW) SendEmailToUser(ctx context.Context, realmName string, userID string, emailRep api.EmailRepresentation) error {
	var action = security.COMSendEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.SendEmailToUser(ctx, realmName, userID, emailRep)
}

func (c *authorizationComponentMW) SendSMS(ctx context.Context, realmName string, smsRep api.SMSRepresentation) error {
	var action = security.COMSendSMS.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.SendSMS(ctx, realmName, smsRep)
}
