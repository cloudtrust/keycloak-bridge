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
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	log "github.com/cloudtrust/common-service/v2/log"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	tokenProvider  *mock.OidcTokenProvider
	keycloakClient *mock.KeycloakClient
	userProfile    *mock.UserProfileCache
	archiveDB      *mock.ArchiveDBModule
	configDB       *mock.ConfigDBModule
	accreditations *mock.AccreditationsServiceClient
	eventsReporter *mock.AuditEventsReporterModule
	glnVerifier    *mock.GlnVerifier
}

func ptrBool(value bool) *bool {
	return &value
}

func createComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		tokenProvider:  mock.NewOidcTokenProvider(mockCtrl),
		keycloakClient: mock.NewKeycloakClient(mockCtrl),
		userProfile:    mock.NewUserProfileCache(mockCtrl),
		archiveDB:      mock.NewArchiveDBModule(mockCtrl),
		configDB:       mock.NewConfigDBModule(mockCtrl),
		eventsReporter: mock.NewAuditEventsReporterModule(mockCtrl),
		accreditations: mock.NewAccreditationsServiceClient(mockCtrl),
		glnVerifier:    mock.NewGlnVerifier(mockCtrl),
	}
}

func (m *componentMocks) NewComponent(realm string) *component {
	return NewComponent(m.tokenProvider, realm, m.keycloakClient, m.userProfile, m.archiveDB, m.configDB,
		m.eventsReporter, m.accreditations, m.glnVerifier, log.NewNopLogger()).(*component)
}

func TestCheckUserConsent(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createComponentMocks(mockCtrl)
	confRealm := "config-realm"
	targetRealm := "social-realm"
	component := mocks.NewComponent(targetRealm)
	accessToken := "==access--token=="
	userID := "user-iden-tif-ier"
	consentCode := "123456"
	ctx := context.WithValue(context.TODO(), cs.CtContextRealm, confRealm)

	t.Run("Load realm admin config fails", func(t *testing.T) {
		anyError := errors.New("any error")
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, confRealm).Return(configuration.RealmAdminConfiguration{}, anyError)
		err := component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.NotNil(t, err)
	})
	t.Run("Consent not required", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, confRealm).Return(configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(false)}, nil)
		err := component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.Nil(t, err)
	})

	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, confRealm).Return(configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(true)}, nil).AnyTimes()

	t.Run("Consent required but not provided", func(t *testing.T) {
		err := component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, nil)
		assert.NotNil(t, err)
		assert.Equal(t, 430, err.(errorhandler.Error).Status)
	})
	t.Run("Consent required but keycloak call fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CheckConsentCodeSMS(accessToken, component.socialRealmName, userID, consentCode).Return(errors.New("any error"))
		err := component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.NotNil(t, err)
		assert.Panics(t, func() { _ = err.(errorhandler.Error) })
	})
	t.Run("Consent required but provided code is invalid", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CheckConsentCodeSMS(accessToken, component.socialRealmName, userID, consentCode).Return(kc.ClientDetailedError{HTTPStatus: 430})
		err := component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, 430, err.(errorhandler.Error).Status)
	})
	t.Run("Consent required and provided code is valid", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CheckConsentCodeSMS(accessToken, component.socialRealmName, userID, consentCode).Return(nil)
		err := component.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, &consentCode)
		assert.Nil(t, err)
	})
}

func TestGetActions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent("realm")

	t.Run("GetActions", func(t *testing.T) {
		res, err := component.GetActions(context.TODO())
		assert.Nil(t, err)
		assert.NotEqual(t, 0, len(res))
	})
}

func TestGetUserByUsername(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	accessToken := "abcd-1234"
	realm := "my-realm"
	username := "utr167x"
	userID := "1234567890"
	grpEndUserID := "11111-22222"
	grpEndUserName := "end_user"
	grpOtherID := "33333-44444"
	grpOtherName := "other_group"
	attrbs := make(kc.Attributes)
	attrbs.SetString(constants.AttrbPhoneNumber, "+417123123123")
	kcUser := kc.UserRepresentation{
		ID:         &userID,
		Username:   &username,
		Attributes: &attrbs,
	}
	kcGroup1 := kc.GroupRepresentation{
		ID:   &grpOtherID,
		Name: &grpOtherName,
	}
	kcGroup2 := kc.GroupRepresentation{
		ID:   &grpEndUserID,
		Name: &grpEndUserName,
	}
	one := 1
	kcUsersSearch := kc.UsersPageRepresentation{Count: &one, Users: []kc.UserRepresentation{kcUser}}
	kcGroupSearch := []kc.GroupRepresentation{kcGroup1, kcGroup2}
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(realm)

	t.Run("Social-Failed to retrieve OIDC token", func(t *testing.T) {
		oidcError := errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		_, err := component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Social-Keycloak GetGroups fails", func(t *testing.T) {
		kcError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, kcError)
		_, err := component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("Social-GetGroups: unknown group", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return([]kc.GroupRepresentation{}, nil)
		_, err := component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})
	mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil).AnyTimes()

	t.Run("Social-Keycloak fails", func(t *testing.T) {
		kcError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, kcError)
		_, err := component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("Social-No user found", func(t *testing.T) {
		none := 0
		searchNoResult := kc.UsersPageRepresentation{Count: &none, Users: []kc.UserRepresentation{}}
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(searchNoResult, nil)
		_, err := component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})
	mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, nil).AnyTimes()

	t.Run("Social-Success", func(t *testing.T) {
		user, err := component.GetUserByUsernameInSocialRealm(ctx, username)
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
		user, err := component.GetUserByUsername(ctx, realm, username)
		assert.Nil(t, err)
		assert.NotNil(t, user)
		assert.Nil(t, user.BirthLocation)
		assert.Equal(t, "+41********23", *user.PhoneNumber)
	})
}

func TestGetUserProfile(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		realm = "my-realm"
		ctx   = context.TODO()
	)

	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(realm)

	t.Run("Error case", func(t *testing.T) {
		mocks.userProfile.EXPECT().GetRealmUserProfile(ctx, component.socialRealmName).Return(kc.UserProfileRepresentation{}, errors.New("any error"))
		_, err := component.GetUserProfileInSocialRealm(ctx)
		assert.NotNil(t, err)
	})
	t.Run("Success case", func(t *testing.T) {
		mocks.userProfile.EXPECT().GetRealmUserProfile(ctx, component.socialRealmName).Return(kc.UserProfileRepresentation{}, nil)
		_, err := component.GetUserProfileInSocialRealm(ctx)
		assert.Nil(t, err)
	})
}

func TestGetUserComponent(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	accessToken := "abcd-1234"
	realm := "my-realm"
	username := "utr167x"
	userID := "1234567890"
	kcUser := kc.UserRepresentation{
		ID:       &userID,
		Username: &username,
	}
	consentRealm := "consent-realm"
	anyError := errors.New("any error")
	realmAdminConfig := configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(false)}
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, consentRealm)

	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(realm)

	t.Run("Social-Failed to retrieve OIDC token", func(t *testing.T) {
		oidcError := errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		_, err := component.GetUserInSocialRealm(ctx, userID, nil)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Social-Consent fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, consentRealm).Return(configuration.RealmAdminConfiguration{}, anyError)
		_, err := component.GetUserInSocialRealm(ctx, userID, nil)
		assert.NotNil(t, err)
	})
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, consentRealm).Return(realmAdminConfig, nil).AnyTimes()

	t.Run("Social-Search in Keycloak fails", func(t *testing.T) {
		kcError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		_, err := component.GetUserInSocialRealm(ctx, userID, nil)
		assert.NotNil(t, err)
	})

	t.Run("Social-Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kcUser, nil)
		user, err := component.GetUserInSocialRealm(ctx, userID, nil)
		assert.Nil(t, err)
		assert.NotNil(t, user)
	})

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	t.Run("Corporate-Consent fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, anyError)
		_, err := component.GetUser(ctx, realm, userID, nil)
		assert.NotNil(t, err)
	})
	realmAdminConfig.ConsentRequiredSocial = ptrBool(true)
	realmAdminConfig.ConsentRequiredCorporate = ptrBool(true)
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, consentRealm).Return(realmAdminConfig, nil).AnyTimes()

	t.Run("Corporate-Success", func(t *testing.T) {
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, anyError)
		_, err := component.GetUser(ctx, realm, userID, nil)
		assert.NotNil(t, err)
	})
}

func createUser(userID, username string, emailVerified bool, phoneNumberVerified bool) kc.UserRepresentation {
	pnv := "false"
	if phoneNumberVerified {
		pnv = "true"
	}
	attributes := kc.Attributes{"phoneNumberVerified": []string{pnv}}
	return kc.UserRepresentation{
		ID:            &userID,
		Username:      &username,
		EmailVerified: &emailVerified,
		Attributes:    &attributes,
	}
}

func TestValidateUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	targetRealm := "cloudtrust"
	validUser := createValidUser()
	userID := "abc789def"
	username := "user_name"
	kcUser := createUser(userID, username, true, true)
	accessToken := "abcdef"
	cfgConsentNotRequired := configuration.RealmAdminConfiguration{ConsentRequiredSocial: ptrBool(false)}
	ctx := context.WithValue(context.TODO(), cs.CtContextRealm, targetRealm)

	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(targetRealm)

	ctx = context.WithValue(ctx, cs.CtContextUsername, "operator")

	mocks.configDB.EXPECT().GetAdminConfiguration(gomock.Any(), gomock.Any()).Return(cfgConsentNotRequired, nil).AnyTimes()

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		oidcError := errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Call to keycloak fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, errors.New("failure"))
		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})

	t.Run("Email not verified", func(t *testing.T) {
		searchResult := createUser(userID, username, false, true)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(searchResult, nil)

		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})

	t.Run("PhoneNumber not verified", func(t *testing.T) {
		searchResult := createUser(userID, username, true, false)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(searchResult, nil)

		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.NotNil(t, err)
	})

	t.Run("Keycloak update fails", func(t *testing.T) {
		kcError := errors.New("keycloak error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)

		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Equal(t, kcError, err)
	})

	t.Run("Notify check fails", func(t *testing.T) {
		dbError := errors.New("db update error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(dbError)

		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Equal(t, dbError, err)
	})

	t.Run("ValidateUserInSocialRealm is successful", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(errors.New("any error"))

		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUserInSocialRealm is successful - Report event fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		err := component.ValidateUserInSocialRealm(ctx, userID, validUser, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUser is successful", func(t *testing.T) {
		ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		err := component.ValidateUser(ctx, targetRealm, userID, validUser, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUser is successful with 1 attachment", func(t *testing.T) {
		ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		validUserWithAttachment := createValidUser()
		validUserWithAttachment.Attachments = &[]apikyc.AttachmentRepresentation{createValidAttachment()}
		err := component.ValidateUser(ctx, targetRealm, userID, validUserWithAttachment, nil)
		assert.Nil(t, err)
	})

	t.Run("ValidateUser is successful with 2 attachments", func(t *testing.T) {
		ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.accreditations.EXPECT().NotifyCheck(ctx, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		validUserWithAttachment := createValidUser()
		validUserWithAttachment.Attachments = &[]apikyc.AttachmentRepresentation{createValidAttachment(), createValidAttachment()}
		err := component.ValidateUser(ctx, targetRealm, userID, validUserWithAttachment, nil)
		assert.Nil(t, err)
	})
}

func TestEnsureContactVerified(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	targetRealm := "cloudtrust"
	userID := "abc789def"
	username := "user_name"
	bFalse := false
	bTrue := true
	verifNotNeeded := configuration.RealmAdminConfiguration{NeedVerifiedContact: &bFalse}
	verifNeeded := configuration.RealmAdminConfiguration{NeedVerifiedContact: &bTrue}
	ctx := context.WithValue(context.TODO(), cs.CtContextRealm, targetRealm)
	anyError := errors.New("any error")

	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(targetRealm)

	t.Run("Email and phone number are both verified", func(t *testing.T) {
		kcUser := createUser(userID, username, true, true)
		err := component.ensureContactVerified(ctx, kcUser)
		assert.Nil(t, err)
	})
	t.Run("Can't get admin configuration", func(t *testing.T) {
		kcUser := createUser(userID, username, true, false)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(configuration.RealmAdminConfiguration{}, anyError)
		err := component.ensureContactVerified(ctx, kcUser)
		assert.Equal(t, anyError, err)
	})
	t.Run("Email and phone number verifications are not needed", func(t *testing.T) {
		kcUser := createUser(userID, username, false, false)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(verifNotNeeded, nil)
		err := component.ensureContactVerified(ctx, kcUser)
		assert.Nil(t, err)
	})
	t.Run("Email not verified", func(t *testing.T) {
		kcUser := createUser(userID, username, false, true)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(verifNeeded, nil)
		err := component.ensureContactVerified(ctx, kcUser)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), constants.Email)
	})
	t.Run("Phone number not verified", func(t *testing.T) {
		kcUser := createUser(userID, username, true, false)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, targetRealm).Return(verifNeeded, nil)
		err := component.ensureContactVerified(ctx, kcUser)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), constants.PhoneNumber)
	})
}

func TestSendSmsConsentCode(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	socialRealm := "social-realm"
	tokenRealm := "token-realm"
	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(socialRealm)

	accessToken := "TOKEN=="
	userID := "1245-7854-8963"
	ctx := context.WithValue(context.TODO(), cs.CtContextRealm, tokenRealm)
	anyError := errors.New("any error")

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
		mocks.eventsReporter.EXPECT().ReportEvent(ctx, gomock.Any())
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	targetRealm := "cloudtrust"
	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(targetRealm)

	accessToken := "TOKEN=="
	userID := "1245-7854-8963"
	ctx := context.TODO()

	t.Run("Social SendSmsCode-Can't get access token", func(t *testing.T) {
		tokenError := errors.New("token error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", tokenError)

		_, err := component.SendSmsCodeInSocialRealm(ctx, userID)
		assert.Equal(t, tokenError, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).AnyTimes()

	t.Run("Social SendSmsCode-Send new sms code", func(t *testing.T) {
		code := "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, component.socialRealmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)
		mocks.eventsReporter.EXPECT().ReportEvent(ctx, gomock.Any())

		codeRes, err := component.SendSmsCodeInSocialRealm(ctx, userID)

		assert.Nil(t, err)
		assert.Equal(t, "1234", codeRes)
	})
	t.Run("Social SendSmsCode-Send new sms code but have error when storing the event in the DB", func(t *testing.T) {
		code := "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, component.socialRealmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
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
		code := "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, targetRealm, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	targetRealm := "cloudtrust"
	mocks := createComponentMocks(mockCtrl)
	component := mocks.NewComponent(targetRealm)

	attachments := []apikyc.AttachmentRepresentation{createValidAttachment()}
	zipBytes, err := component.zipAttachments(attachments)
	assert.Nil(t, err)

	buf := bytes.NewReader(zipBytes)
	reader, _ := zip.NewReader(buf, buf.Size())
	for i, f := range reader.File {
		rc, _ := f.Open()

		content := make([]byte, len(*attachments[i].Content))
		_, _ = rc.Read(content)
		assert.Equal(t, *attachments[i].Content, content)
	}
}
