package kyc

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/configuration"
	log "github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetActions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDetailsDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)

	var component = NewComponent(mockTokenProvider, "realm", mockKeycloakClient, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

	t.Run("GetActions", func(t *testing.T) {
		var res, err = component.GetActions(context.TODO())
		assert.Nil(t, err)
		assert.NotEqual(t, 0, len(res))
	})
}

func TestGetUserByUsernameInSocialRealmComponent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDetailsDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)

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

	var component = NewComponent(mockTokenProvider, realm, mockKeycloakClient, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetGroups from Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, kcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetGroups: unknown group", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, realm).Return([]kc.GroupRepresentation{}, nil)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetUserByUsername from Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, kcError)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetUserByUsernameInSocialRealm from Keycloak fails", func(t *testing.T) {
		var none = 0
		var searchNoResult = kc.UsersPageRepresentation{Count: &none, Users: []kc.UserRepresentation{}}
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(searchNoResult, nil)
		var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
		assert.NotNil(t, err)
	})

	t.Run("GetUserByUsernameInSocialRealm success", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, realm).Return(kcGroupSearch, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, realm, realm, prmQryUserName, username, "groupId", grpEndUserID).Return(kcUsersSearch, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, realm, *kcUser.ID).Return(dto.DBUser{
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

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDetailsDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)

	var accessToken = "abcd-1234"
	var realm = "my-realm"
	var username = "utr167x"
	var userID = "1234567890"
	var kcUser = kc.UserRepresentation{
		ID:       &userID,
		Username: &username,
	}
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	var component = NewComponent(mockTokenProvider, realm, mockKeycloakClient, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var _, err = component.GetUserInSocialRealm(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUserInSocialRealm from Keycloak fails", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUserInSocialRealm(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUserInSocialRealm from DB fails", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kcUser, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, realm, *kcUser.ID).Return(dto.DBUser{}, errors.New("database"))
		var _, err = component.GetUserInSocialRealm(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUserInSocialRealm success", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kcUser, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, realm, *kcUser.ID).Return(dto.DBUser{
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

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDetailsDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)

	var targetRealm = "cloudtrust"
	var validUser = createValidUser()
	var userID = "abc789def"
	var username = "user_name"
	var kcUser = createUser(userID, username, true, true)
	var accessToken = "abcdef"
	var ctx = context.TODO()
	var dbUser = dto.DBUser{UserID: &userID}

	var component = NewComponent(mockTokenProvider, targetRealm, mockKeycloakClient, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

	ctx = context.WithValue(ctx, cs.CtContextUsername, "operator")

	t.Run("Failed to retrieve OIDC token", func(t *testing.T) {
		var oidcError = errors.New("oidc error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", oidcError)
		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Call to accreditations module fails", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, errors.New("failure"))
		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Email not verified", func(t *testing.T) {
		var searchResult = createUser(userID, username, false, true)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(searchResult, 0, nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("PhoneNumber not verified", func(t *testing.T) {
		var searchResult = createUser(userID, username, true, false)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(searchResult, 0, nil)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("SQL error when searching user in database", func(t *testing.T) {
		var sqlError = errors.New("sql error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dto.DBUser{}, sqlError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Keycloak update fails", func(t *testing.T) {
		var kcError = errors.New("keycloak error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Equal(t, kcError, err)
	})

	t.Run("Update user in DB fails", func(t *testing.T) {
		var dbError = errors.New("db update error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(dbError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Equal(t, dbError, err)
	})

	t.Run("Store check in DB fails", func(t *testing.T) {
		var dbError = errors.New("db update error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(dbError)

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Equal(t, dbError, err)
	})

	t.Run("ValidateUserInSocialRealm is successful", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Nil(t, err)
	})

	t.Run("ValidateUserInSocialRealm is successful - Report event fails", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
		mockUsersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any()).Return(errors.New("report fails"))

		var err = component.ValidateUserInSocialRealm(ctx, userID, validUser)
		assert.Nil(t, err)
	})
}

func TestValidateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDetailsDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)

	var targetRealm = "cloudtrust"
	var validUser = createValidUser()
	var userID = "abc789def"
	var username = "user_name"
	var kcUser = createUser(userID, username, true, true)
	var accessToken = "abcdef"
	var ctx = context.TODO()
	var dbUser = dto.DBUser{UserID: &userID}

	var component = NewComponent(mockTokenProvider, targetRealm, mockKeycloakClient, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextUsername, "operator")

	mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, configuration.CheckKeyPhysical).Return(kcUser, 0, nil)
	mockUsersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dbUser, nil)
	mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
	mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
	mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
	mockEventsDB.EXPECT().ReportEvent(gomock.Any(), "VALIDATE_USER", "back-office", gomock.Any())

	var err = component.ValidateUser(ctx, targetRealm, userID, validUser)
	assert.Nil(t, err)

}
