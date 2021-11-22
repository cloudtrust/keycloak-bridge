package tasks

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
)

var actions []security.Action

func newAction(as string, scope security.Scope) security.Action {
	a := security.Action{
		Name:  as,
		Scope: scope,
	}

	actions = append(actions, a)
	return a
}

// Actions used for authorization module
var (
	TSKDeleteDeniedToUUsers = newAction("TSK_DeleteDeniedToUUsers", security.ScopeGlobal)
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// GetActions returns available actions
func GetActions() []security.Action {
	return actions
}

// MakeAuthorizationManagementComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationManagementComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (a *authorizationComponentMW) CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx context.Context) error {
	var action = TSKDeleteDeniedToUUsers.String()
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := a.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return a.next.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
}
