package account

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/internal/security"
	"github.com/go-kit/kit/log"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        AccountComponent
}

// MakeAuthorizationManagementComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationManagementComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(AccountComponent) AccountComponent {
	return func(next AccountComponent) AccountComponent {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (c *authorizationComponentMW) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	var action = "AC_UpdatePassword"
	var targetRealm = ctx.Value("realm").(string)
	var userID = ctx.Value("userId").(string)

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}
	return c.next.UpdatePassword(ctx, currentPassword, newPassword, confirmPassword)
}
