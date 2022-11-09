package kyc

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	log "github.com/cloudtrust/common-service/v2/log"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	tokenProvider  *mock.OidcTokenProvider
	keycloakClient *mock.KeycloakClient
	archiveDB      *mock.ArchiveDBModule
	configDB       *mock.ConfigDBModule
	eventsDB       *mock.EventsDBModule
	accreditations *mock.AccreditationsServiceClient
	glnVerifier    *mock.GlnVerifier
}

func ptrBool(value bool) *bool {
	return &value
}

func createComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		tokenProvider:  mock.NewOidcTokenProvider(mockCtrl),
		keycloakClient: mock.NewKeycloakClient(mockCtrl),
		archiveDB:      mock.NewArchiveDBModule(mockCtrl),
		configDB:       mock.NewConfigDBModule(mockCtrl),
		eventsDB:       mock.NewEventsDBModule(mockCtrl),
		accreditations: mock.NewAccreditationsServiceClient(mockCtrl),
		glnVerifier:    mock.NewGlnVerifier(mockCtrl),
	}
}

func (m *componentMocks) NewComponent(realm string) *component {
	return NewComponent(m.tokenProvider, realm, m.keycloakClient, m.archiveDB, m.configDB,
		m.eventsDB, m.accreditations, m.glnVerifier, log.NewNopLogger()).(*component)
}

func TestCheckUserConsent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var confRealm = "config-realm"
	var targetRealm = "social-realm"
	var component = mocks.NewComponent(targetRealm)
	var accessToken = "==access--token=="
	var userID = "user-iden-tif-ier"
	var consentCode = "123456"
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, confRealm)

	t.Run("Load realm admin config fails", func(t *testing.T) {
		var anyError = errors.New("any error")
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, confRealm).Return(configuration.RealmAdminConfiguration{}, anyError)
		var err = component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.NotNil(t, err)
	})
	t.Run("Consent not required", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, confRealm).Return(configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(false)}, nil)
		var err = component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.Nil(t, err)
	})

	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, confRealm).Return(configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(true)}, nil).AnyTimes()

	t.Run("Consent required but not provided", func(t *testing.T) {
		var err = component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, nil)
		assert.NotNil(t, err)
		assert.Equal(t, 430, err.(errorhandler.Error).Status)
	})
	t.Run("Consent required but keycloak call fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CheckConsentCodeSMS(accessToken, component.socialRealmName, userID, consentCode).Return(errors.New("any error"))
		var err = component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.NotNil(t, err)
		assert.Panics(t, func() { var _ = err.(errorhandler.Error) })
	})
	t.Run("Consent required but provided code is invalid", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CheckConsentCodeSMS(accessToken, component.socialRealmName, userID, consentCode).Return(kc.ClientDetailedError{HTTPStatus: 430})
		var err = component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, 430, err.(errorhandler.Error).Status)
	})
	t.Run("Consent required and provided code is valid", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CheckConsentCodeSMS(accessToken, component.socialRealmName, userID, consentCode).Return(nil)
		var err = component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.Nil(t, err)
	})
}

func TestGetActions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent("realm")

	t.Run("GetActions", func(t *testing.T) {
		var res, err = component.GetActions(context.TODO())
		assert.Nil(t, err)
		assert.NotEqual(t, 0, len(res))
	})
}

func TestGetUserByUsername(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var accessToken = "abcd-1234"
	var realm = "my-realm"
	var username = "utr167x"
	var userID = "1234567890"
	var grpEndUserID = "11111-22222"
	var grpEndUserName = "end_user"
	var grpOtherID = "33333-44444"
	var grpOtherName = "other_group"
	var attrbs = make(kc.Attributes)
	attrbs.SetString(constants.AttrbPhoneNumber, "+417123123123")
	var kcUser = kc.UserRepresentation{
		ID:         &userID,
		Username:   &username,
		Attributes: &attrbs,
	}
	var kcGroup1 = kc.GroupRepresentation{
		ID:   &grpOtherID,
		Name: &grpOtherName,
	}
	var kcGroup2 = kc.GroupRepresentation{
		ID:   &grpEndUserID,
		Name: &grpEndUserName,
	}
	var one = 1
	var kcUsersSearch = kc.UsersPageRepresentation{Count: &one, Users: []kc.UserRepresentation{kcUser}}
	var kcGroupSearch = []kc.GroupRepresentation{kcGroup1, kcGroup2}
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(realm)

	t.Run("Social-Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Social-Keycloak GetGroups fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, kcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("Social-GetGroups: unknown group", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return([]kc.GroupRepresentation{}, nil)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})
	mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil).AnyTimes()

	t.Run("Social-Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, kcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("Social-No user found", func(t *testing.T) {
		var none = 0
		var searchNoResult = kc.UsersPageRepresentation{Count: &none, Users: []kc.UserRepresentation{}}
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(searchNoResult, nil)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})
	mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, nil).AnyTimes()

	t.Run("Social-Success", func(t *testing.T) {
		var user, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.Nil(t, err)
		assert.NotNil(t, user)
		assert.Nil(t, user.BirthLocation)
		assert.Equal(t, "+41********23", *user.PhoneNumber)
	})

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	t.Run("Corporate-Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username).Return(kcUsersSearch, nil).AnyTimes()
		mocks.keycloakClient.EXPECT().GetGroupsOfUser(accessToken, realm, userID).Return([]kc.GroupRepresentation{kcGroup1}, nil)
		var user, err = component.GetUserByUsername(ctx, realm, username)
		assert.Nil(t, err)
		assert.NotNil(t, user)
		assert.Nil(t, user.BirthLocation)
		assert.Equal(t, "+41********23", *user.PhoneNumber)
	})
}

func TestGetUserComponent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var accessToken = "abcd-1234"
	var realm = "my-realm"
	var username = "utr167x"
	var userID = "1234567890"
	var kcUser = kc.UserRepresentation{
		ID:       &userID,
		Username: &username,
	}
	var consentRealm = "consent-realm"
	var anyError = errors.New("any error")
	var realmAdminConfig = configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(false)}
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, consentRealm)

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(realm)

	t.Run("Social-Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var _, err = component.GetUserInSocialRealm(ctx, userID, nil)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Social-Consent fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, consentRealm).Return(configuration.RealmAdminConfiguration{}, anyError)
		var _, err = component.GetUserInSocialRealm(ctx, userID, nil)
		assert.NotNil(t, err)
	})
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, consentRealm).Return(realmAdminConfig, nil).AnyTimes()

	t.Run("Social-Search in Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUserInSocialRealm(ctx, userID, nil)
		assert.NotNil(t, err)
	})

	t.Run("Social-Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kcUser, nil)
		var user, err = component.GetUserInSocialRealm(ctx, userID, nil)
		assert.Nil(t, err)
		assert.NotNil(t, user)
	})

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	t.Run("Corporate-Consent fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, anyError)
		var _, err = component.GetUser(ctx, realm, userID, nil)
		assert.NotNil(t, err)
	})
	realmAdminConfig.ConsentRequiredSocial = ptrBool(true)
	realmAdminConfig.ConsentRequiredCorporate = ptrBool(true)
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, consentRealm).Return(realmAdminConfig, nil).AnyTimes()

	t.Run("Corporate-Success", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, anyError)
		var _, err = component.GetUser(ctx, realm, userID, nil)
		assert.NotNil(t, err)
	})
}

func createUser(userID, username string, emailVerified bool, phoneNumberVerified bool) kc.UserRepresentation {
	var pnv = "false"
	if phoneNumberVerified {
		pnv = "true"
	}
	var attributes = kc.Attributes{"phoneNumberVerified": []string{pnv}}
	return kc.UserRepresentation{
		ID:            &userID,
		Username:      &username,
		EmailVerified: &emailVerified,
		Attributes:    &attributes,
	}
}

func TestValidateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var targetRealm = "cloudtrust"
	var validUser = createValidUser()
	var userID = "abc789def"
	var username = "user_name"
	var kcUser = createUser(userID, username, true, true)
	var accessToken = "abcdef"
	var cfgConsentNotRequired = configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(false)}
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, targetRealm)

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(targetRealm)

	ctx = context.WithValue(ctx, cs.CtContextUsername, "operator")

	mocks.configDB.EXPECT().GetAdminConfiguration(gomock.Any(), gomock.Any()).Return(cfgConsentNotRequired, nil).AnyTimes()

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Call to keycloak fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, errors.New("failure"))
		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})

	t.Run("Email not verified", func(t *testing.T) {
		var searchResult = createUser(userID, username, false, true)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(searchResult, nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})

	t.Run("PhoneNumber not verified", func(t *testing.T) {
		var searchResult = createUser(userID, username, true, false)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(searchResult, nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})

	t.Run("Keycloak update fails", func(t *testing.T) {
		var kcError = errors.New("keycloak error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Equal(t, kcError, err)
	})

	t.Run("Notify check fails", func(t *testing.T) {
		var dbError = errors.New("db update error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(dbError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Equal(t, dbError, err)
	})

	t.Run("ValidateUserInSocialRealm is successful", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(errors.New("any error"))

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUserInSocialRealm is successful - Report event fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any()).Return(errors.New("report fails"))
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUser is successful", func(t *testing.T) {
		ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		var err = component.ValidateUser(ctx, targetRealm, userID, validUser, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUser is successful with 1 attachment", func(t *testing.T) {
		ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		validUserWithAttachment := createValidUser()
		validUserWithAttachment.Attachments = &[]apikyc.AttachmentRepresentation{createValidAttachment()}
		var err = component.ValidateUser(ctx, targetRealm, userID, validUserWithAttachment, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUser is successful with 2 attachments", func(t *testing.T) {
		ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		validUserWithAttachment := createValidUser()
		validUserWithAttachment.Attachments = &[]apikyc.AttachmentRepresentation{createValidAttachment(), createValidAttachment()}
		var err = component.ValidateUser(ctx, targetRealm, userID, validUserWithAttachment, nil)
		assert.Nil(t, err)
	})
}

func TestEnsureContactVerified(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var targetRealm = "cloudtrust"
	var userID = "abc789def"
	var username = "user_name"
	var bFalse = false
	var bTrue = true
	var verifNotNeeded = configuration.RealmAdminConfiguration{NeedVerifiedContact: &bFalse}
	var verifNeeded = configuration.RealmAdminConfiguration{NeedVerifiedContact: &bTrue}
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, targetRealm)
	var anyError = errors.New("any error")

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(targetRealm)

	t.Run("Email and phone number are both verified", func(t *testing.T) {
		var kcUser = createUser(userID, username, true, true)
		var err = component.ensureContactVerified(ctx, kcUser)
		assert.Nil(t, err)
	})
	t.Run("Can't get admin configuration", func(t *testing.T) {
		var kcUser = createUser(userID, username, true, false)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(configuration.RealmAdminConfiguration{}, anyError)
		var err = component.ensureContactVerified(ctx, kcUser)
		assert.Equal(t, anyError, err)
	})
	t.Run("Email and phone number verifications are not needed", func(t *testing.T) {
		var kcUser = createUser(userID, username, false, false)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(verifNotNeeded, nil)
		var err = component.ensureContactVerified(ctx, kcUser)
		assert.Nil(t, err)
	})
	t.Run("Email not verified", func(t *testing.T) {
		var kcUser = createUser(userID, username, false, true)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(verifNeeded, nil)
		var err = component.ensureContactVerified(ctx, kcUser)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), constants.Email)
	})
	t.Run("Phone number not verified", func(t *testing.T) {
		var kcUser = createUser(userID, username, true, false)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(verifNeeded, nil)
		var err = component.ensureContactVerified(ctx, kcUser)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), constants.PhoneNumber)
	})
}

func TestSendSmsConsentCode(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var socialRealm = "social-realm"
	var tokenRealm = "token-realm"
	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(socialRealm)

	var accessToken = "TOKEN=="
	var userID = "1245-7854-8963"
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, tokenRealm)
	var anyError = errors.New("any error")

	t.Run("Social SendSmsConsentCode-Can't get access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)

		err := component.SendSmsConsentCodeInSocialRealm(ctx, userID)
		assert.Equal(t, anyError, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).AnyTimes()

	t.Run("Social SendSmsConsentCode-Can't get realm admin configuration", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(gomock.Any(), tokenRealm).Return(configuration.RealmAdminConfiguration{}, anyError)
		err := component.SendSmsConsentCodeInSocialRealm(ctx, userID)
		assert.Equal(t, anyError, err)
	})

	t.Run("Social SendSmsConsentCode-Consent is not enabled", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(gomock.Any(), tokenRealm).Return(configuration.RealmAdminConfiguration{}, nil)
		err := component.SendSmsConsentCodeInSocialRealm(ctx, userID)
		assert.NotNil(t, err)
	})
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, tokenRealm).Return(configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(true)}, nil).AnyTimes()

	t.Run("Social SendSmsConsentCode-Keycloak call fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendConsentCodeSMS(accessToken, component.socialRealmName, userID).Return(anyError)
		err := component.SendSmsConsentCodeInSocialRealm(ctx, userID)
		assert.Equal(t, anyError, err)
	})

	t.Run("Social SendSmsConsentCode-Keycloak call fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendConsentCodeSMS(accessToken, component.socialRealmName, userID).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(ctx, "SMS_CONSENT", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		err := component.SendSmsConsentCodeInSocialRealm(ctx, userID)
		assert.Nil(t, err)
	})

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)

	t.Run("Corporate SendSmsConsentCode-Consent is not enabled", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(gomock.Any(), tokenRealm).Return(configuration.RealmAdminConfiguration{}, nil)
		err := component.SendSmsConsentCode(ctx, tokenRealm, userID)
		assert.NotNil(t, err)
	})
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, tokenRealm).Return(configuration.RealmAdminConfiguration{ConsentRequiredCorporate: ptrBool(true)}, nil).AnyTimes()

	t.Run("Corporate SendSmsConsentCode-Keycloak call fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendConsentCodeSMS(accessToken, tokenRealm, userID).Return(anyError)
		err := component.SendSmsConsentCode(ctx, tokenRealm, userID)
		assert.Equal(t, anyError, err)
	})
}

func TestSendSmsCode(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var targetRealm = "cloudtrust"
	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(targetRealm)

	var accessToken = "TOKEN=="
	var userID = "1245-7854-8963"
	var ctx = context.TODO()

	t.Run("Social SendSmsCode-Can't get access token", func(t *testing.T) {
		var tokenError = errors.New("token error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", tokenError)

		_, err := component.SendSmsCodeInSocialRealm(ctx, userID)
		assert.Equal(t, tokenError, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).AnyTimes()

	t.Run("Social SendSmsCode-Send new sms code", func(t *testing.T) {
		var code = "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, component.socialRealmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)
		mocks.eventsDB.EXPECT().ReportEvent(ctx, "SMS_CHALLENGE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		codeRes, err := component.SendSmsCodeInSocialRealm(ctx, userID)

		assert.Nil(t, err)
		assert.Equal(t, "1234", codeRes)
	})
	t.Run("Social SendSmsCode-Send new sms code but have error when storing the event in the DB", func(t *testing.T) {
		var code = "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, component.socialRealmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)

		mocks.eventsDB.EXPECT().ReportEvent(ctx, "SMS_CHALLENGE", "back-office", database.CtEventRealmName, component.socialRealmName, database.CtEventUserID, userID).Return(errors.New("error"))
		codeRes, err := component.SendSmsCodeInSocialRealm(ctx, userID)

		assert.Nil(t, err)
		assert.Equal(t, "1234", codeRes)
	})
	t.Run("Social SendSmsCode-Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, component.socialRealmName, userID).Return(kc.SmsCodeRepresentation{}, fmt.Errorf("Invalid input"))

		_, err := component.SendSmsCodeInSocialRealm(ctx, userID)

		assert.NotNil(t, err)
	})

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)

	t.Run("Corporate SendSmsCode-Send new sms code", func(t *testing.T) {
		var code = "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, targetRealm, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)
		mocks.eventsDB.EXPECT().ReportEvent(ctx, "SMS_CHALLENGE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		codeRes, err := component.SendSmsCode(ctx, targetRealm, userID)

		assert.Nil(t, err)
		assert.Equal(t, "1234", codeRes)
	})
}

func createValidAttachment() apikyc.AttachmentRepresentation {
	var (
		contentBase  = "basicvalueofsomecharacters"
		contentBytes = []byte(contentBase + contentBase + contentBase + contentBase)
	)
	return apikyc.AttachmentRepresentation{Filename: ptr("filename.pdf"), ContentType: ptr("application/pdf"), Content: &contentBytes}
}

func TestZipAttachments(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var targetRealm = "cloudtrust"
	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(targetRealm)

	var attachments = []apikyc.AttachmentRepresentation{createValidAttachment()}
	zipBytes, err := component.zipAttachments(attachments)
	assert.Nil(t, err)

	buf := bytes.NewReader(zipBytes)
	reader, _ := zip.NewReader(buf, buf.Size())
	for i, f := range reader.File {
		rc, _ := f.Open()

		content := make([]byte, len(*attachments[i].Content))
		rc.Read(content)
		assert.Equal(t, *attachments[i].Content, content)
	}
}
