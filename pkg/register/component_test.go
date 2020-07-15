package register

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/configuration"
	errorhandler "github.com/cloudtrust/common-service/errors"
	log "github.com/cloudtrust/common-service/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func createValidUser() apiregister.UserRepresentation {
	var (
		gender        = "M"
		firstName     = "Marc"
		lastName      = "El-Bichoun"
		email         = "marcel.bichon@elca.ch"
		phoneNumber   = "00 33 686 550011"
		birthDate     = "31.03.2001"
		birthLocation = "Montreux"
		docType       = "ID_CARD"
		docNumber     = "MEL123789654ABC"
		docExp        = "28.02.2050"
		locale        = "fr"
	)

	return apiregister.UserRepresentation{
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		Email:                &email,
		PhoneNumber:          &phoneNumber,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		IDDocumentType:       &docType,
		IDDocumentNumber:     &docNumber,
		IDDocumentExpiration: &docExp,
		Locale:               &locale,
	}
}

func ptrString(value string) *string {
	return &value
}

func TestGroupIDsResolution(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)

	var targetRealm = "cloudtrust"
	var group1 = kc.GroupRepresentation{ID: ptrString("id-group-1"), Name: ptrString("name-group-1")}
	var group2 = kc.GroupRepresentation{ID: ptrString("id-group-2"), Name: ptrString("name-group-2")}
	var group3 = kc.GroupRepresentation{ID: ptrString("id-group-3"), Name: ptrString("name-group-3")}
	var enduserGroups = []string{*group1.Name, *group3.Name}
	var groups = []kc.GroupRepresentation{group1, group2, group3}
	var accessToken = "an-access-token"
	var anyString = "???"
	var anError = errors.New("any error")

	t.Run("ProvideToken fails", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, anError)
		var _, err = NewComponent(anyString, targetRealm, anyString, anyString, enduserGroups, nil, mockTokenProvider, nil, nil, nil, nil)
		assert.Equal(t, anError, err)
	})
	mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("GetGroups fails", func(t *testing.T) {
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealm).Return(nil, anError)
		var _, err = NewComponent(anyString, targetRealm, anyString, anyString, enduserGroups, mockKeycloakClient, mockTokenProvider, nil, nil, nil, nil)
		assert.Equal(t, anError, err)
	})
	t.Run("Unknown groups", func(t *testing.T) {
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealm).Return([]kc.GroupRepresentation{}, nil)
		var _, err = NewComponent(anyString, targetRealm, anyString, anyString, enduserGroups, mockKeycloakClient, mockTokenProvider, nil, nil, nil, nil)
		assert.NotNil(t, err)
	})
	mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealm).Return(groups, nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		var res, err = NewComponent(anyString, targetRealm, anyString, anyString, enduserGroups, mockKeycloakClient, mockTokenProvider, nil, nil, nil, nil)
		assert.Nil(t, err)
		assert.Len(t, res.(*component).registerEndUserGroups, len(enduserGroups))
	})
}

func createComponent(keycloakURL, targetRealm, ssePublicURL, enduserClientID string, enduserGroups []string, keycloakClient *mock.KeycloakClient, tokenProvider *mock.OidcTokenProvider, usersDB *mock.UsersDBModule, configDB *mock.ConfigurationDBModule, eventsDB *mock.EventsDBModule) Component {
	var accessToken = "the-access-token"
	var group1ID = "end_user-group-id"
	var group1Name = "end_user"
	var group1 = kc.GroupRepresentation{ID: &group1ID, Name: &group1Name}
	var groups = []kc.GroupRepresentation{group1}
	tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
	keycloakClient.EXPECT().GetGroups(accessToken, targetRealm).Return(groups, nil)

	var c, _ = NewComponent(keycloakURL, targetRealm, ssePublicURL, enduserClientID, enduserGroups, keycloakClient, tokenProvider, usersDB, configDB, eventsDB, log.NewNopLogger())
	return c
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
	var enduserGroups = []string{"end_user"}
	var confRealm = "test"
	var validUser = createValidUser()
	var accessToken = "abcdef"
	var empty = 0
	var usersSearchResult = kc.UsersPageRepresentation{Count: &empty}
	var component = createComponent(keycloakURL, targetRealm, ssePublicURL, enduserClientID, enduserGroups, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB)

	t.Run("User is not valid", func(t *testing.T) {
		// User is not valid
		var _, err = component.RegisterUser(ctx, confRealm, apiregister.UserRepresentation{})
		assert.NotNil(t, err)
	})

	t.Run("Can't get realm configuration from DB", func(t *testing.T) {
		var dbError = errors.New("db error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, dbError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, dbError, err)
	})

	t.Run("Can't get access token", func(t *testing.T) {
		var tokenError = errors.New("token error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", tokenError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, tokenError, err)
	})

	t.Run("checkExistingUser fails", func(t *testing.T) {
		var kcError = errors.New("kc GetUsers error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(kc.UsersPageRepresentation{}, kcError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.NotNil(t, err)
	})

	t.Run("Can't generate unused username", func(t *testing.T) {
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(accessToken, targetRealm, targetRealm, gomock.Any()).
			Return("", errorhandler.Error{Status: http.StatusConflict, Message: "keycloak.existing.username"}).
			Times(10)

		var _, err = component.RegisterUser(ctx, confRealm, validUser)
		assert.NotNil(t, err)
	})

	t.Run("Create user in Keycloak fails", func(t *testing.T) {
		var keycloakError = errors.New("keycloak create error")
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(accessToken, targetRealm, targetRealm, gomock.Any()).Return("", keycloakError)

		var _, err = component.RegisterUser(ctx, confRealm, validUser)
		assert.Equal(t, keycloakError, err)
	})

	t.Run("Update user in KC fails", func(t *testing.T) {
		var updateError = errors.New("update error")
		var userID = "abc789def"
		var one = 1
		var disabled = false
		var user = kc.UserRepresentation{ID: &userID, Email: validUser.Email, EmailVerified: &disabled}
		var userExistsSearch = kc.UsersPageRepresentation{
			Count: &one,
			Users: []kc.UserRepresentation{user},
		}
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(userExistsSearch, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(updateError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, updateError, err)
	})

	t.Run("DB: Create or update user fails", func(t *testing.T) {
		var insertError = errors.New("insert error")
		var token = "abcdef"
		var userID = "abc789def"
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(insertError)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Equal(t, insertError, err)
	})

	t.Run("No required actions. RegisterUser is successful", func(t *testing.T) {
		var token = "abcdef"
		var userID = "abc789def"
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), "REGISTER_USER", "back-office", gomock.Any()).Return(nil)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Nil(t, err)
	})

	t.Run("Everything is ok but report event fails", func(t *testing.T) {
		var token = "abcdef"
		var userID = "abc789def"
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(configuration.RealmConfiguration{}, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), "REGISTER_USER", "back-office", gomock.Any()).Return(errors.New("report event error"))

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.Nil(t, err)
	})

	t.Run("Parse keycloak URL fails", func(t *testing.T) {
		var token = "abcdef"
		var userID = "abc789def"
		var requiredActions = []string{"execute", "actions"}
		var successURL = "http://couldtrust.ch"
		var enduserGroups = []string{"end_user"}
		var realmConfiguration = configuration.RealmConfiguration{RegisterExecuteActions: &requiredActions, RedirectSuccessfulRegistrationURL: &successURL}
		var component = createComponent("not\nvalid\nURL", targetRealm, "", "", enduserGroups, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB)

		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(realmConfiguration, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)

		var _, err = component.RegisterUser(ctx, confRealm, createValidUser())
		assert.NotNil(t, err)
	})

	t.Run("Send execute actions mail fails", func(t *testing.T) {
		var sendActionsError = errors.New("send actions error")
		var token = "abcdef"
		var userID = "abc789def"
		var requiredActions = []string{"execute", "actions"}
		var successURL = "http://couldtrust.ch"
		var realmConfiguration = configuration.RealmConfiguration{RegisterExecuteActions: &requiredActions, RedirectSuccessfulRegistrationURL: &successURL}
		mockConfigDB.EXPECT().GetConfiguration(ctx, confRealm).Return(realmConfiguration, nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(token, nil)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealm, targetRealm, "email", *validUser.Email).Return(usersSearchResult, nil)
		mockKeycloakClient.EXPECT().CreateUser(token, targetRealm, targetRealm, gomock.Any()).Return(userID, nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)
		mockKeycloakClient.EXPECT().ExecuteActionsEmail(token, targetRealm, userID, requiredActions, "client_id", gomock.Any(), "redirect_uri", gomock.Any()).DoAndReturn(
			func(_ string, _ string, _ string, _ []string, _ string, _ string, _ string, fullURL string) error {
				expectedSubStringURL := "%2F" + targetRealm + "%2Fconfirmation%2F" + confRealm
				assert.True(t, strings.Contains(fullURL, expectedSubStringURL))
				return sendActionsError
			})

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
	var enduserGroups = []string{"end_user"}
	var targetRealm = "trustid"
	var email = "user@trustid.swiss"
	var userID = "ab54f9a-97bi94"
	var user = apiregister.UserRepresentation{Email: &email}
	var verified = true
	var keycloakUser = kc.UserRepresentation{ID: &userID}
	var empty = 0
	var one = 1
	var foundUsers = kc.UsersPageRepresentation{Count: &one, Users: []kc.UserRepresentation{keycloakUser}}

	var component = &component{keycloakURL, targetRealm, ssePublicURL, enduserClientID, enduserGroups, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB, log.NewNopLogger()}

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
	var enduserGroups = []string{"end_user"}
	var targetRealm = "cloudtrust"
	var confRealm = "test"
	var component = createComponent(keycloakURL, targetRealm, ssePublicURL, enduserClientID, enduserGroups, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB)

	t.Run("Retrieve configuration successfully", func(t *testing.T) {
		// Retrieve configuration successfully
		mockConfigDB.EXPECT().GetConfiguration(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, nil)
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.Nil(t, err)
	})

	t.Run("Retrieve configuration in DB fails", func(t *testing.T) {
		// Retrieve configuration in DB fails
		mockConfigDB.EXPECT().GetConfiguration(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, errors.New("GetConfiguration fails"))
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.NotNil(t, err)
	})
}
