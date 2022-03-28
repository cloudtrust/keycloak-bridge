package keycloakb

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	// Account can be replaced after 10 days
	duration           = 240 * time.Hour
	overridedRealmName = "overrided"
	source             = "the-source"
)

var (
	mapRealmsOverride = map[string]string{overridedRealmName: source}
)

type onboardingMocks struct {
	keycloakClient      *mock.OnboardingKeycloakClient
	usersDBModule       *mock.UsersDBModule
	keycloakURIProvider *mock.KeycloakURIProvider
}

func createOnboardingMocks(mockCtrl *gomock.Controller) *onboardingMocks {
	return &onboardingMocks{
		keycloakClient:      mock.NewOnboardingKeycloakClient(mockCtrl),
		usersDBModule:       mock.NewUsersDBModule(mockCtrl),
		keycloakURIProvider: mock.NewKeycloakURIProvider(mockCtrl),
	}
}

func (om *onboardingMocks) createOnboardingModule() *onboardingModule {
	var mockLogger = log.NewNopLogger()
	return NewOnboardingModule(om.keycloakClient, om.keycloakURIProvider, om.usersDBModule, duration, mapRealmsOverride, mockLogger).(*onboardingModule)
}

func TestOnboardingAlreadyCompleted(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createOnboardingMocks(mockCtrl)
	var onboardingModule = mocks.createOnboardingModule()

	t.Run("No attributes", func(t *testing.T) {
		var kcUser = kc.UserRepresentation{}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted attribute missing", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetString("test", "wrong")
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted attribute with invalid value", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetString(constants.AttrbOnboardingCompleted, "wrong")
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.NotNil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted is true", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetBool(constants.AttrbOnboardingCompleted, true)
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.True(t, res)
	})

	t.Run("OnboardingCompleted is false", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetBool(constants.AttrbOnboardingCompleted, false)
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})
}

func TestSendOnboardingEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createOnboardingMocks(mockCtrl)
	var onboardingModule = mocks.createOnboardingModule()

	var keycloakBaseURI = "http://keycloak.url"
	var realmName = "realmName"
	var themeRealmName = "themeRealmName"
	var accessToken = "ACCESS_TOKEN"
	var userID = "135-15641-546"
	var username = "username"
	var onboardingClientID = "onboardingid"
	var onboardingRedirectURI = "http://redirect.test/test/example"
	var expectedActionsNoReminder = []string{"VERIFY_EMAIL", "set-onboarding-token", "onboarding-action"}
	var expectedActionsWithReminder = []string{"VERIFY_EMAIL", "set-onboarding-token", "onboarding-action", "reminder-action"}
	var ctx = context.TODO()

	mocks.keycloakURIProvider.EXPECT().GetBaseURI(realmName).Return(keycloakBaseURI).AnyTimes()

	t.Run("Failed to perform ExecuteActionEmail without reminder", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, expectedActionsNoReminder,
			"client_id", onboardingClientID, "redirect_uri", gomock.Any(), "themeRealm", themeRealmName).Return(errors.New("unexpected error"))
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, themeRealmName, false)

		assert.NotNil(t, err)
	})
	t.Run("Failed to perform ExecuteActionEmail with reminder", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, expectedActionsWithReminder,
			"client_id", onboardingClientID, "redirect_uri", gomock.Any(), "themeRealm", themeRealmName).Return(errors.New("unexpected error"))
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, themeRealmName, true)

		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		var paramKV = []string{"customX", "valueX"}
		var embeddedURI = url.QueryEscape(onboardingRedirectURI)
		var expectedFullURI = "http://keycloak.url/auth/realms/" + realmName + "/protocol/openid-connect/auth?client_id=" + onboardingClientID + "&login_hint=" + username + "&redirect_uri=" + embeddedURI + "&response_type=code&scope=openid"
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, expectedActionsNoReminder,
			"client_id", onboardingClientID, "redirect_uri", gomock.Any(), "themeRealm", themeRealmName, "customX", "valueX").DoAndReturn(
			func(_, _, _, _ string, _ []string, params ...string) error {
				// params: _, _, _ string, redirectURI string, _, _, _, _ interface{}
				_, err := url.Parse(params[3])
				assert.Nil(t, err)
				assert.Equal(t, expectedFullURI, params[3])
				return nil
			})
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, themeRealmName, false, paramKV...)

		assert.Nil(t, err)
	})
}

func TestCreateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createOnboardingMocks(mockCtrl)
	var onboarding = mocks.createOnboardingModule()

	var realm = "cloudtrust"
	var targetRealm = "client"
	var ctx = context.Background()
	var accessToken = "__TOKEN__"
	var kcUser = kc.UserRepresentation{}

	t.Run("Can't generate username", func(t *testing.T) {
		var errExistingUsername = errorhandler.Error{
			Status:  http.StatusConflict,
			Message: "keycloak.existing.username",
		}

		mocks.keycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errExistingUsername).Times(10)
		var _, err = onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "username.generation")
	})
	t.Run("User creation fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("any error"))
		var _, err = onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		var userID = "12345678-abcd-9876"
		var location = "http://location/users/" + userID
		kcUser.Username = nil

		mocks.keycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(location, nil)

		var resPath, err = onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser)
		assert.Nil(t, err)
		var matched, errRegexp = regexp.Match(`^\d{8}$`, []byte(*kcUser.Username))
		assert.True(t, matched && errRegexp == nil)
		assert.Contains(t, resPath, *kcUser.ID)
	})
}

func TestProcessAlreadyExistingUserCases(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createOnboardingMocks(mockCtrl)
	var onboarding = mocks.createOnboardingModule()

	var ctx = context.TODO()
	var accessToken = "access-token"
	var targetRealmName = "target-realm"
	var userID = "user-id"
	var username = "12345678"
	var userEmail = "user@email.com"
	var realmRep = kc.RealmRepresentation{}
	var usersPageRep = kc.UsersPageRepresentation{}
	var createdTimestamp = time.Now().Unix()
	var anyError = errors.New("any error")
	var notSupposedToBeCalled = func(pUsername string, pCreatedTimestamp int64, pThirdParty *string) error {
		assert.Fail(t, "not supposed to be executed")
		return nil
	}
	var attrbs kc.Attributes = map[kc.AttributeKey][]string{}

	t.Run("Can't get realm from keycloak", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, targetRealmName).Return(realmRep, anyError)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.NotNil(t, err)
	})

	t.Run("Duplicate emails allowed", func(t *testing.T) {
		realmRep.DuplicateEmailsAllowed = ptrBool(true)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, targetRealmName).Return(realmRep, nil)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Nil(t, err)
	})

	realmRep.DuplicateEmailsAllowed = ptrBool(false)
	mocks.keycloakClient.EXPECT().GetRealm(accessToken, targetRealmName).Return(realmRep, nil).AnyTimes()

	t.Run("GetUsers fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, anyError)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.NotNil(t, err)
	})

	t.Run("No already existing user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Nil(t, err)
	})

	t.Run("User already exists-Onboarding completed is invalid", func(t *testing.T) {
		attrbs[constants.AttrbOnboardingCompleted] = []string{"failure"}
		usersPageRep.Count = ptrInt(1)
		usersPageRep.Users = []kc.UserRepresentation{{
			ID:               &userID,
			Username:         &username,
			Email:            &userEmail,
			CreatedTimestamp: &createdTimestamp,
			Attributes:       &attrbs,
		}}
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.NotNil(t, err)
	})

	t.Run("User already exists-Already onboarded", func(t *testing.T) {
		attrbs[constants.AttrbOnboardingCompleted] = []string{"true"}
		usersPageRep.Users[0].Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil)

		var errAlreadyOnboarded = errors.New("already onboarded")
		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, func(pUsername string, pCreatedTimestamp int64, pThirdParty *string) error {
			assert.Equal(t, username, pUsername)
			assert.Equal(t, createdTimestamp, pCreatedTimestamp)
			assert.Nil(t, pThirdParty)
			return errAlreadyOnboarded
		})
		assert.Equal(t, errAlreadyOnboarded, err)
	})

	t.Run("User already exists-Created by third party", func(t *testing.T) {
		var thirdPartyName = "third-party-name"
		attrbs[constants.AttrbOnboardingCompleted] = []string{"false"}
		attrbs[constants.AttrbSource] = []string{thirdPartyName}
		usersPageRep.Users[0].Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil)

		var errCreatedByThirdPart = errors.New("already onboarded")
		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, func(pUsername string, pCreatedTimestamp int64, pThirdParty *string) error {
			assert.Equal(t, username, pUsername)
			assert.Equal(t, createdTimestamp, pCreatedTimestamp)
			assert.Equal(t, thirdPartyName, *pThirdParty)
			return errCreatedByThirdPart
		})
		assert.Equal(t, errCreatedByThirdPart, err)
	})

	attrbs[constants.AttrbSource] = []string{overridedRealmName}
	usersPageRep.Users[0].Attributes = &attrbs
	mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil).AnyTimes()

	t.Run("User already exists-Cant remove Keycloak user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, userID).Return(anyError)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Equal(t, anyError, err)
	})
	mocks.keycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, userID).Return(nil).AnyTimes()

	t.Run("User already exists-Cant remove DB user", func(t *testing.T) {
		mocks.usersDBModule.EXPECT().DeleteUserDetails(ctx, targetRealmName, userID).Return(anyError)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Equal(t, anyError, err)
	})

	t.Run("User already exists-Successfully removed", func(t *testing.T) {
		mocks.usersDBModule.EXPECT().DeleteUserDetails(ctx, targetRealmName, userID).Return(nil)

		var err = onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Nil(t, err)
	})
}

func TestCanReplaceAccount(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createOnboardingMocks(mockCtrl)
	var onboarding = mocks.createOnboardingModule()

	t.Run("Too old account can be replaced", func(t *testing.T) {
		assert.True(t, onboarding.canReplaceAccount(time.Now().Add(-2*duration).Unix(), ptr("one-source"), "any-realm"))
	})
	t.Run("Can replace user account created without src attribute", func(t *testing.T) {
		assert.True(t, onboarding.canReplaceAccount(time.Now().Unix(), nil, ""))
	})
	t.Run("Can replace user account created by register", func(t *testing.T) {
		assert.True(t, onboarding.canReplaceAccount(time.Now().Unix(), ptr("register"), "any-realm"))
	})
	t.Run("Can replace user account created by same source", func(t *testing.T) {
		assert.True(t, onboarding.canReplaceAccount(time.Now().Unix(), ptr("same-source"), "same-source"))
	})
	t.Run("Can't replace user account created by other source", func(t *testing.T) {
		assert.False(t, onboarding.canReplaceAccount(time.Now().Unix(), ptr("one-source"), "any-realm"))
	})
}
