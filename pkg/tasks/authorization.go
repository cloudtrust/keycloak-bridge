package tasks

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// MakeAuthorizationTasksComponentMW creates the tasks middleware
func MakeAuthorizationTasksComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (a *authorizationComponentMW) CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx context.Context) error {
	var action = security.TSKDeleteDeniedToUUsers.String()
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := a.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return a.next.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
}
