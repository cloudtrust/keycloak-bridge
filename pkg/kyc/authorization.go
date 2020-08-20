package kyc

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/middleware"
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
	KYCGetActions                     = newAction("KYC_GetActions", security.ScopeGlobal)
	KYCGetUserInSocialRealm           = newAction("KYC_GetUserInSocialRealm", security.ScopeRealm)
	KYCGetUserByUsernameInSocialRealm = newAction("KYC_GetUserByUsernameInSocialRealm", security.ScopeRealm)
	KYCValidateUserInSocialRealm      = newAction("KYC_ValidateUserInSocialRealm", security.ScopeRealm)
	KYCValidateUser                   = newAction("KYC_ValidateUser", security.ScopeGroup)
)

type authorizationComponentMW struct {
	realmName           string
	authManager         security.AuthorizationManager
	availabilityChecker middleware.EndpointAvailabilityChecker
	logger              log.Logger
	next                Component
}

// GetActions returns available actions
func GetActions() []security.Action {
	return actions
}

// MakeAuthorizationRegisterComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationRegisterComponentMW(realmName string, authorizationManager security.AuthorizationManager, availabilityChecker middleware.EndpointAvailabilityChecker, logger log.Logger) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			realmName:           realmName,
			authManager:         authorizationManager,
			availabilityChecker: availabilityChecker,
			logger:              logger,
			next:                next,
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

func (c *authorizationComponentMW) GetUserByUsernameInSocialRealm(ctx context.Context, username string) (apikyc.UserRepresentation, error) {
	var action = KYCGetUserByUsernameInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the configured social realm.
	var targetRealm = c.realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUserByUsernameInSocialRealm(ctx, username)
}

func (c *authorizationComponentMW) GetUserInSocialRealm(ctx context.Context, userID string) (apikyc.UserRepresentation, error) {
	var action = KYCGetUserInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the configured social realm.
	var targetRealm = c.realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUserInSocialRealm(ctx, userID)
}

func (c *authorizationComponentMW) ValidateUserInSocialRealm(ctx context.Context, userID string, user apikyc.UserRepresentation) error {
	var action = KYCValidateUserInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the configured social realm.
	var targetRealm = c.realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.ValidateUserInSocialRealm(ctx, userID, user)
}

func (c *authorizationComponentMW) ValidateUser(ctx context.Context, realmName string, userID string, user apikyc.UserRepresentation) error {
	var err error
	ctx, err = c.availabilityChecker.CheckAvailabilityForRealm(ctx, realmName, c.logger)
	if err != nil {
		return err
	}

	var action = KYCValidateUser.String()
	var targetRealm = realmName

	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ValidateUser(ctx, realmName, userID, user)
}
