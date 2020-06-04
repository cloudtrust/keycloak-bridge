package kyc

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
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

// Creates constants for API method names
var (
	KYCGetActions        = newAction("KYC_GetActions", security.ScopeGlobal)
	KYCGetUser           = newAction("KYC_GetUser", security.ScopeGroup)
	KYCGetUserByUsername = newAction("KYC_GetUserByUsername", security.ScopeRealm)
	KYCValidateUser      = newAction("KYC_ValidateUser", security.ScopeGroup)
)

type authorizationComponentMW struct {
	realmName   string
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// GetActions returns available actions
func GetActions() []security.Action {
	return actions
}

// MakeAuthorizationRegisterComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationRegisterComponentMW(realmName string, logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			realmName:   realmName,
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) GetActions(ctx context.Context) ([]apikyc.ActionRepresentation, error) {
	var action = KYCGetActions.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []apikyc.ActionRepresentation{}, err
	}

	return c.next.GetActions(ctx)
}

func (c *authorizationComponentMW) GetUserByUsername(ctx context.Context, username string) (apikyc.UserRepresentation, error) {
	var action = KYCGetUserByUsername.String()
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUserByUsername(ctx, username)
}

func (c *authorizationComponentMW) GetUser(ctx context.Context, userID string) (apikyc.UserRepresentation, error) {
	var action = KYCGetUser.String()
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, userID)
}

func (c *authorizationComponentMW) ValidateUser(ctx context.Context, userID string, user apikyc.UserRepresentation) error {
	var action = KYCValidateUser.String()
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ValidateUser(ctx, userID, user)
}
