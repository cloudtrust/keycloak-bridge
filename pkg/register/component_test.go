package register

import (
	"context"
	"errors"
	"net/http"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/errors"
	log "github.com/cloudtrust/common-service/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func createValidUser() apiregister.User {
	var (
		gender      = "M"
		firstName   = "Marc"
		lastName    = "El-Bichoun"
		email       = "marcel.bichon@elca.ch"
		phoneNumber = "00 33 686 550011"
	)

	return apiregister.User{
		Gender:       &gender,
		FirstName:    &firstName,
		LastName:     &lastName,
		EmailAddress: &email,
		PhoneNumber:  &phoneNumber,
	}
}

func TestRegisterUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)
	var mockConfigDB = mock.NewConfigurationDBModule(mockCtrl)
	var mockUsersDB = mock.NewUsersDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)

	var ctx = context.TODO()
	var targetRealm = "cloudtrust"
	var keycloakURL = "https://idp.trustid.ch"
	var ssePublicURL = "https://sse.trustid.ch"
	var enduserClientID = "selfserviceid"
	var confRealm = "test"
	var validUser = createValidUser()
	var accessToken = "abcdef"
	var empty = 0
	var usersSearchResult = kc.UsersPageRepresentation{Count: &empty}
	var component = NewComponent(keycloakURL, targetRealm, ssePublicURL, enduserClientID, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB, log.NewNopLogger())

	t.Run("User is not valid", func(t *testing.T) {
		// User is not valid
		var _, err = component.RegisterUser(ctx, confRealm, apiregister.User{})
		assert.NotNil(t, err)
	})

	t.Run("Can't get realm configuration from DB", func(t *testing.T) {
		var dbError = errors.New("db error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, dbError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, dbError, err)
	})

	t.Run("Can't get access token", func(t *testing.T) {
		var tokenError = errors.New("token error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", tokenError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, tokenError, err)
	})

	t.Run("checkExistingUser fails", func(t *testing.T) {
		var kcError = errors.New("kc GetUsers error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.EmailAddress).Return(kc.UsersPageRepresentation{}, kcError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.NotNil(t, err)
	})

	t.Run("Can't generate unused username", func(t *testing.T) {
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.EmailAddress).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(accessToken, targetRealm, targetRealm, gomock.Any()).
			Return("", errorhandler.Error{Status: http.StatusConflict, Message: "keycloak.existing.username"}).
			Times(10)

		var _, err = component.RegisterUser(ctx, confRealm, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Create user in Keycloak fails", func(t *testing.T) {
		var keycloakError = errors.New("keycloak create error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.EmailAddress).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(accessToken, targetRealm, targetRealm, gomock.Any()).Return("", keycloakError)

		var _, err = component.RegisterUser(ctx, confRealm, validUser)
		assert.Equal(t, keycloakError, err)
	})

	t.Run("Update user in KC fails", func(t *testing.T) {
		var updateError = errors.New("update error")
		var userID = "abc789def"
		var one = 1
		var disabled = false
		var user = kc.UserRepresentation{Id: &userID, Email: validUser.EmailAddress, EmailVerified: &disabled}
		var userExistsSearch = kc.UsersPageRepresentation{
			Count: &one,
			Users: []kc.UserRepresentation{user},
		}
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.EmailAddress).Return(userExistsSearch, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(updateError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, updateError, err)
	})

	t.Run("DB: Create or update user fails", func(t *testing.T) {
		var insertError = errors.New("insert error")
		var token = "abcdef"
		var userID = "abc789def"
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.EmailAddress).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(insertError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, insertError, err)
	})

	t.Run("No required actions. RegisterUser is successful", func(t *testing.T) {
		var token = "abcdef"
		var userID = "abc789def"
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(dto.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.EmailAddress).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), "REGISTER_USER", "back-office", gomock.Any())

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Nil(t, err)
	})

	t.Run("Send execute actions mail fails", func(t *testing.T) {
		var sendActionsError = errors.New("send actions error")
		var token = "abcdef"
		var userID = "abc789def"
		var requiredActions = []string{"execute", "actions"}
		var successURL = "http://couldtrust.ch"
		var realmConfiguration = dto.RealmConfiguration{RegisterExecuteActions: &requiredActions, RedirectSuccessfulRegistrationURL: &successURL}
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(realmConfiguration, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.EmailAddress).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)
		mockKeycloakClient.EXPECT().ExecuteActionsEmail(token, targetRealm, userID, requiredActions, gomock.Any()).Return(sendActionsError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, sendActionsError, err)
	})
}

func TestCheckExistingUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)
	var mockConfigDB = mock.NewConfigurationDBModule(mockCtrl)
	var mockUsersDB = mock.NewUsersDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)

	var ctx = context.TODO()
	var accessToken = "123-456-789"
	var keycloakURL = "https://idp.trustid.ch"
	var ssePublicURL = "https://sse.trustid.ch"
	var enduserClientID = "selfserviceid"
	var targetRealm = "trustid"
	var email = "user@trustid.swiss"
	var userID = "ab54f9a-97bi94"
	var user = apiregister.User{EmailAddress: &email}
	var verified = true
	var keycloakUser = kc.UserRepresentation{Id: &userID}
	var empty = 0
	var one = 1
	var foundUsers = kc.UsersPageRepresentation{Count: &one, Users: []kc.UserRepresentation{keycloakUser}}

	var component = &component{keycloakURL, targetRealm, ssePublicURL, enduserClientID, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB, log.NewNopLogger()}

	t.Run("GetUsers fails", func(t *testing.T) {
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", email).Return(foundUsers, errors.New("GetUsers fails"))

		var _, err = component.checkExistingUser(ctx, accessToken, user)

		assert.NotNil(t, err)
	})

	t.Run("GetUsers: not found", func(t *testing.T) {
		var usersNotFound = kc.UsersPageRepresentation{Count: &empty}
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", email).Return(usersNotFound, nil)

		var user, err = component.checkExistingUser(ctx, accessToken, user)

		assert.Nil(t, err)
		assert.Nil(t, user)
	})

	t.Run("Keycloak GetUser fails", func(t *testing.T) {
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", email).Return(foundUsers, nil)

		var _, err = component.checkExistingUser(ctx, accessToken, user)

		assert.NotNil(t, err)
	})

	t.Run("User is validated in Keycloak", func(t *testing.T) {
		foundUsers.Users[0].EmailVerified = &verified
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", email).Return(foundUsers, nil)

		var _, err = component.checkExistingUser(ctx, accessToken, user)

		assert.NotNil(t, err)
	})
}

func TestGetConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)
	var mockConfigDB = mock.NewConfigurationDBModule(mockCtrl)
	var mockUsersDB = mock.NewUsersDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)

	var ctx = context.TODO()
	var keycloakURL = "https://idp.trustid.ch"
	var ssePublicURL = "https://sse.trustid.ch"
	var enduserClientID = "selfserviceid"
	var targetRealm = "cloudtrust"
	var confRealm = "test"
	var component = NewComponent(keycloakURL, targetRealm, ssePublicURL, enduserClientID, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB, log.NewNopLogger())

	t.Run("Retrieve configuration successfully", func(t *testing.T) {
		// Retrieve configuration successfully
		mockConfigDB.EXPECT().GetConfiguration(gomock.Any(), gomock.Any()).Return(dto.RealmConfiguration{}, nil)
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.Nil(t, err)
	})

	t.Run("Retrieve configuration in DB fails", func(t *testing.T) {
		// Retrieve configuration in DB fails
		mockConfigDB.EXPECT().GetConfiguration(gomock.Any(), gomock.Any()).Return(dto.RealmConfiguration{}, errors.New("GetConfiguration fails"))
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.NotNil(t, err)
	})
}
