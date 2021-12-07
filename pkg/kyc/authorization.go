package kyc

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/middleware"
	"github.com/cloudtrust/common-service/v2/security"
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
	KYCGetActions                      = newAction("KYC_GetActions", security.ScopeGlobal)
	KYCGetUserInSocialRealm            = newAction("KYC_GetUserInSocialRealm", security.ScopeRealm)
	KYCGetUser                         = newAction("KYC_GetUser", security.ScopeGroup)
	KYCGetUserByUsernameInSocialRealm  = newAction("KYC_GetUserByUsernameInSocialRealm", security.ScopeRealm)
	KYCGetUserByUsername               = newAction("KYC_GetUserByUsername", security.ScopeGroup)
	KYCValidateUserInSocialRealm       = newAction("KYC_ValidateUserInSocialRealm", security.ScopeRealm)
	KYCValidateUser                    = newAction("KYC_ValidateUser", security.ScopeGroup)
	KYCSendSmsConsentCodeInSocialRealm = newAction("KYC_SendSmsConsentCodeInSocialRealm", security.ScopeRealm)
	KYCSendSmsConsentCode              = newAction("KYC_SendSmsConsentCode", security.ScopeGroup)
	KYCSendSmsCodeInSocialRealm        = newAction("KYC_SendSmsCodeInSocialRealm", security.ScopeRealm)
	KYCSendSmsCode                     = newAction("KYC_SendSmsCode", security.ScopeGroup)
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
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUserByUsernameInSocialRealm(ctx, username)
}

func (c *authorizationComponentMW) GetUserByUsername(ctx context.Context, realmName string, username string) (apikyc.UserRepresentation, error) {
	var res apikyc.UserRepresentation
	var _, err = c.availabilityChecker.CheckAvailabilityForRealm(ctx, realmName, c.logger)
	if err != nil {
		return res, err
	}

	// First call component
	res, err = c.next.GetUserByUsername(ctx, realmName, username)
	if err != nil {
		return res, err
	}

	// Check authorization according to the found user
	var action = KYCGetUserByUsername.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, *res.ID); err != nil {
		return apikyc.UserRepresentation{}, errorhandler.CreateNotFoundError("user")
	}

	return res, nil
}

func (c *authorizationComponentMW) GetUserInSocialRealm(ctx context.Context, userID string, consentCode *string) (apikyc.UserRepresentation, error) {
	var action = KYCGetUserInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUserInSocialRealm(ctx, userID, consentCode)
}

func (c *authorizationComponentMW) GetUser(ctx context.Context, realmName string, userID string, consentCode *string) (apikyc.UserRepresentation, error) {
	var err error
	ctx, err = c.availabilityChecker.CheckAvailabilityForRealm(ctx, realmName, c.logger)
	if err != nil {
		return apikyc.UserRepresentation{}, err
	}

	var action = KYCGetUser.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, userID); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, realmName, userID, consentCode)
}

func (c *authorizationComponentMW) ValidateUserInSocialRealm(ctx context.Context, userID string, user apikyc.UserRepresentation, consentCode *string) error {
	var action = KYCValidateUserInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.ValidateUserInSocialRealm(ctx, userID, user, consentCode)
}

func (c *authorizationComponentMW) ValidateUser(ctx context.Context, realmName string, userID string, user apikyc.UserRepresentation, consentCode *string) error {
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

	return c.next.ValidateUser(ctx, realmName, userID, user, consentCode)
}

func (c *authorizationComponentMW) SendSmsConsentCodeInSocialRealm(ctx context.Context, userID string) error {
	var action = KYCSendSmsConsentCodeInSocialRealm.String()
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.SendSmsConsentCodeInSocialRealm(ctx, userID)
}

func (c *authorizationComponentMW) SendSmsConsentCode(ctx context.Context, realmName string, userID string) error {
	var err error
	ctx, err = c.availabilityChecker.CheckAvailabilityForRealm(ctx, realmName, c.logger)
	if err != nil {
		return err
	}

	var action = KYCSendSmsConsentCode.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, userID); err != nil {
		return err
	}

	return c.next.SendSmsConsentCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SendSmsCodeInSocialRealm(ctx context.Context, userID string) (string, error) {
	var action = KYCSendSmsCodeInSocialRealm.String()
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.SendSmsCodeInSocialRealm(ctx, userID)
}

func (c *authorizationComponentMW) SendSmsCode(ctx context.Context, realmName string, userID string) (string, error) {
	var err error
	ctx, err = c.availabilityChecker.CheckAvailabilityForRealm(ctx, realmName, c.logger)
	if err != nil {
		return "", err
	}

	var action = KYCSendSmsCode.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, userID); err != nil {
		return "", err
	}

	return c.next.SendSmsCode(ctx, realmName, userID)
}
