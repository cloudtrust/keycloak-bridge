package kyc

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/configuration"
	log "github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	tokenProvider  *mock.OidcTokenProvider
	keycloakClient *mock.KeycloakClient
	usersDB        *mock.UsersDetailsDBModule
	archiveDB      *mock.ArchiveDBModule
	configDB       *mock.ConfigDBModule
	eventsDB       *mock.EventsDBModule
	accreditations *mock.AccreditationsModule
}

func createComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		tokenProvider:  mock.NewOidcTokenProvider(mockCtrl),
		keycloakClient: mock.NewKeycloakClient(mockCtrl),
		usersDB:        mock.NewUsersDetailsDBModule(mockCtrl),
		archiveDB:      mock.NewArchiveDBModule(mockCtrl),
		configDB:       mock.NewConfigDBModule(mockCtrl),
		eventsDB:       mock.NewEventsDBModule(mockCtrl),
		accreditations: mock.NewAccreditationsModule(mockCtrl),
	}
}

func (m *componentMocks) NewComponent(realm string) *component {
	return NewComponent(m.tokenProvider, realm, m.keycloakClient, m.usersDB, m.archiveDB, m.configDB,
		m.eventsDB, m.accreditations, log.NewNopLogger()).(*component)
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

func TestGetUserByUsernameInSocialRealmComponent(t *testing.T) {
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
	var kcUser = kc.UserRepresentation{
		ID:       &userID,
		Username: &username,
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

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetGroups from Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, kcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetGroups: unknown group", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return([]kc.GroupRepresentation{}, nil)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetUserByUsername from Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil)
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, kcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetUserByUsernameInSocialRealm from Keycloak fails", func(t *testing.T) {
		var none = 0
		var searchNoResult = kc.UsersPageRepresentation{Count: &none, Users: []kc.UserRepresentation{}}
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil)
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(searchNoResult, nil)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetUserByUsernameInSocialRealm success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil)
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, realm, *kcUser.ID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		var user, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.Nil(t, err)
		assert.NotNil(t, user)
	})
}

func TestGetUserInSocialRealmComponent(t *testing.T) {
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
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(realm)

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var _, err = component.GetUserInSocialRealm(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUserInSocialRealm from Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUserInSocialRealm(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUserInSocialRealm from DB fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kcUser, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, realm, *kcUser.ID).Return(dto.DBUser{}, errors.New("database"))
		var _, err = component.GetUserInSocialRealm(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUserInSocialRealm success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kcUser, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, realm, *kcUser.ID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		var user, err = component.GetUserInSocialRealm(ctx, userID)
		assert.Nil(t, err)
		assert.NotNil(t, user)
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

func TestValidateUserInSocialRealm(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var targetRealm = "cloudtrust"
	var validUser = createValidUser()
	var userID = "abc789def"
	var username = "user_name"
	var kcUser = createUser(userID, username, true, true)
	var accessToken = "abcdef"
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, targetRealm)
	var dbUser = dto.DBUser{UserID: &userID}

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(targetRealm)

	ctx = context.WithValue(ctx, cs.CtContextUsername, "operator")

	mocks.configDB.EXPECT().GetAdminConfiguration(gomock.Any(), gomock.Any()).Return(configuration.RealmAdminConfiguration{}, nil).AnyTimes()

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Call to accreditations module fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, errors.New("failure"))
		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Email not verified", func(t *testing.T) {
		var searchResult = createUser(userID, username, false, true)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(searchResult, 0, nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("PhoneNumber not verified", func(t *testing.T) {
		var searchResult = createUser(userID, username, true, false)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(searchResult, 0, nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("SQL error when searching user in database", func(t *testing.T) {
		var sqlError = errors.New("sql error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dto.DBUser{}, sqlError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Keycloak update fails", func(t *testing.T) {
		var kcError = errors.New("keycloak error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Equal(t, kcError, err)
	})

	t.Run("Update user in DB fails", func(t *testing.T) {
		var dbError = errors.New("db update error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(dbError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Equal(t, dbError, err)
	})

	t.Run("Store check in DB fails", func(t *testing.T) {
		var dbError = errors.New("db update error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(dbError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Equal(t, dbError, err)
	})

	t.Run("ValidateUserInSocialRealm is successful", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())
		mocks.usersDB.EXPECT().GetChecks(gomock.Any(), targetRealm, userID).Return([]dto.DBCheck{}, errors.New("any error"))
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(errors.New("any error"))

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Nil(t, err)
	})

	t.Run("ValidateUserInSocialRealm is successful - Report event fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any()).Return(errors.New("report fails"))
		mocks.usersDB.EXPECT().GetChecks(gomock.Any(), targetRealm, userID).Return([]dto.DBCheck{}, nil)
		mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Nil(t, err)
	})
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
	var ctx = context.TODO()
	var dbUser = dto.DBUser{UserID: &userID}

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.NewComponent(targetRealm)

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextUsername, "operator")

	mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
	mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
	mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
	mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
	mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
	mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())
	mocks.usersDB.EXPECT().GetChecks(gomock.Any(), targetRealm, userID).Return([]dto.DBCheck{}, nil)
	mocks.archiveDB.EXPECT().StoreUserDetails(gomock.Any(), targetRealm, gomock.Any()).Return(nil)

	var err = component.ValidateUser(ctx, targetRealm, userID, validUser)
	assert.Nil(t, err)
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
