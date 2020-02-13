package kyc

import (
	"context"

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

const (
	// RegistrationOfficer is the name of the Keycloak group required for KYC API methods
	RegistrationOfficer = "registration_officer"
)

// Creates constants for API method names
var (
	KYCGetActions        = newAction("KYC_GetActions", security.ScopeGlobal)
	KYCGetUser           = newAction("KYC_GetUser", security.ScopeGroup)
	KYCGetUserByUsername = newAction("KYC_GetUserByUsername", security.ScopeGroup)
	KYCValidateUser      = newAction("KYC_ValidateUser", security.ScopeGroup)
)

type authorizationComponentMW struct {
	realmName   string
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
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
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []apikyc.ActionRepresentation{}, err
	}

	return c.next.GetActions(ctx)
}

func (c *authorizationComponentMW) GetUserByUsername(ctx context.Context, username string, groupIDs []string) (apikyc.UserRepresentation, error) {
	var action = KYCGetUserByUsername.String()
	var targetRealm = c.realmName

	for _, groupID := range groupIDs {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
			return apikyc.UserRepresentation{}, err
		}
	}

	return c.next.GetUserByUsername(ctx, username, groupIDs)
}

func (c *authorizationComponentMW) GetUser(ctx context.Context, userID string) (apikyc.UserRepresentation, error) {
	var action = KYCGetUser.String()
	var targetRealm = c.realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, userID)
}

func (c *authorizationComponentMW) ValidateUser(ctx context.Context, userID string, user apikyc.UserRepresentation) error {
	var action = KYCValidateUser.String()
	var targetRealm = c.realmName
	var groupID = RegistrationOfficer

	if err := c.authManager.CheckAuthorizationOnTargetGroup(ctx, action, targetRealm, groupID); err != nil {
		return err
	}

	return c.next.ValidateUser(ctx, userID, user)
}
