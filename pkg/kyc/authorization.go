package kyc

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/middleware"
	"github.com/cloudtrust/common-service/v2/security"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
)

type authorizationComponentMW struct {
	realmName           string
	authManager         security.AuthorizationManager
	availabilityChecker middleware.EndpointAvailabilityChecker
	logger              log.Logger
	next                Component
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
	var action = security.KYCGetActions.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []apikyc.ActionRepresentation{}, err
	}

	return c.next.GetActions(ctx)
}

func (c *authorizationComponentMW) GetUserProfile(ctx context.Context, realmName string) (apicommon.ProfileRepresentation, error) {
	var action = security.KYCGetRealmUserProfile.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realmName); err != nil {
		return apicommon.ProfileRepresentation{}, err
	}

	return c.next.GetUserProfile(ctx, realmName)
}

func (c *authorizationComponentMW) GetUserProfileInSocialRealm(ctx context.Context) (apicommon.ProfileRepresentation, error) {
	var action = security.KYCGetRealmUserProfileInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return apicommon.ProfileRepresentation{}, err
	}

	return c.next.GetUserProfileInSocialRealm(ctx)
}

func (c *authorizationComponentMW) GetUserByUsernameInSocialRealm(ctx context.Context, username string) (apikyc.UserRepresentation, error) {
	var action = security.KYCGetUserByUsernameInSocialRealm.String()

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
	var action = security.KYCGetUserByUsername.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, *res.ID); err != nil {
		return apikyc.UserRepresentation{}, errorhandler.CreateNotFoundError("user")
	}

	return res, nil
}

func (c *authorizationComponentMW) GetUserInSocialRealm(ctx context.Context, userID string, consentCode *string) (apikyc.UserRepresentation, error) {
	var action = security.KYCGetUserInSocialRealm.String()

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

	var action = security.KYCGetUser.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, userID); err != nil {
		return apikyc.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, realmName, userID, consentCode)
}

func (c *authorizationComponentMW) ValidateUserInSocialRealm(ctx context.Context, userID string, user apikyc.UserRepresentation, consentCode *string) error {
	var action = security.KYCValidateUserInSocialRealm.String()

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

	var action = security.KYCValidateUser.String()
	var targetRealm = realmName

	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ValidateUser(ctx, realmName, userID, user, consentCode)
}

/********************* (BEGIN) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/
func (c *authorizationComponentMW) ValidateUserBasicID(ctx context.Context, userID string, user apikyc.UserRepresentation) error {
	var action = security.KYCValidateUserBasicID.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.ValidateUserBasicID(ctx, userID, user)
}

/********************* (END) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/

func (c *authorizationComponentMW) SendSmsConsentCodeInSocialRealm(ctx context.Context, userID string) error {
	var action = security.KYCSendSmsConsentCodeInSocialRealm.String()
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

	var action = security.KYCSendSmsConsentCode.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, userID); err != nil {
		return err
	}

	return c.next.SendSmsConsentCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SendSmsCodeInSocialRealm(ctx context.Context, userID string) (string, error) {
	var action = security.KYCSendSmsCodeInSocialRealm.String()
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

	var action = security.KYCSendSmsCode.String()
	if err = c.authManager.CheckAuthorizationOnTargetUser(ctx, action, realmName, userID); err != nil {
		return "", err
	}

	return c.next.SendSmsCode(ctx, realmName, userID)
}
