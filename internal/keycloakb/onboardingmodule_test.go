package keycloakb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	// Account can be replaced after 10 days
	duration           = 240 * time.Hour
	overridedRealmName = "overrided"
	source             = "the-source"
)

var mapRealmsOverride = map[string]string{overridedRealmName: source}

type onboardingMocks struct {
	keycloakClient      *mock.OnboardingKeycloakClient
	keycloakURIProvider *mock.KeycloakURIProvider
}

func createOnboardingMocks(mockCtrl *gomock.Controller) *onboardingMocks {
	return &onboardingMocks{
		keycloakClient:      mock.NewOnboardingKeycloakClient(mockCtrl),
		keycloakURIProvider: mock.NewKeycloakURIProvider(mockCtrl),
	}
}

func (om *onboardingMocks) createOnboardingModule() *onboardingModule {
	mockLogger := log.NewNopLogger()
	return NewOnboardingModule(om.keycloakClient, om.keycloakURIProvider, duration, mapRealmsOverride, mockLogger).(*onboardingModule)
}

func TestOnboardingAlreadyCompleted(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createOnboardingMocks(mockCtrl)
	onboardingModule := mocks.createOnboardingModule()

	t.Run("No attributes", func(t *testing.T) {
		kcUser := kc.UserRepresentation{}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted attribute missing", func(t *testing.T) {
		attributes := make(kc.Attributes)
		attributes.SetString("test", "wrong")
		kcUser := kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted attribute with invalid value", func(t *testing.T) {
		attributes := make(kc.Attributes)
		attributes.SetString(constants.AttrbOnboardingCompleted, "wrong")
		kcUser := kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.NotNil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted is true", func(t *testing.T) {
		attributes := make(kc.Attributes)
		attributes.SetBool(constants.AttrbOnboardingCompleted, true)
		kcUser := kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.True(t, res)
	})

	t.Run("OnboardingCompleted is false", func(t *testing.T) {
		attributes := make(kc.Attributes)
		attributes.SetBool(constants.AttrbOnboardingCompleted, false)
		kcUser := kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})
}

func TestSendOnboardingEmail(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createOnboardingMocks(mockCtrl)
	onboardingModule := mocks.createOnboardingModule()

	keycloakBaseURI := "http://keycloak.url"
	realmName := "realmName"
	themeRealmName := "themeRealmName"
	accessToken := "ACCESS_TOKEN"
	userID := "135-15641-546"
	username := "username"
	onboardingClientID := "onboardingid"
	onboardingRedirectURI := "http://redirect.test/test/example"
	expectedActionsNoReminder := []string{"VERIFY_EMAIL", "set-onboarding-token", "onboarding-action"}
	expectedActionsWithReminder := []string{"VERIFY_EMAIL", "set-onboarding-token", "onboarding-action", "reminder-action"}
	ctx := context.TODO()

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
		paramKV := []string{"customX", "valueX"}
		embeddedURI := url.QueryEscape(onboardingRedirectURI)
		expectedFullURI := "http://keycloak.url/auth/realms/" + realmName + "/protocol/openid-connect/auth?client_id=" + onboardingClientID + "&login_hint=" + username + "&redirect_uri=" + embeddedURI + "&response_type=code&scope=openid"
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

func TestComputeRedirectURI(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createOnboardingMocks(mockCtrl)
	onboarding := mocks.createOnboardingModule()

	keycloakBaseURI := "http://keycloak.url"
	realmName := "realmName"
	accessToken := "ACCESS_TOKEN"
	userID := "135-15641-546"
	username := "username"
	onboardingClientID := "onboardingid"
	onboardingRedirectURI := "http://redirect.test/test/example"
	onboardingRedirectURIEncoded := "http%3A%2F%2Fredirect.test%2Ftest%2Fexample"
	trustIDAuthToken := "plktqQ+H9sENTTyYv+9jQ4BwSCEF2agtohyrSZWSo3o="
	trustIDAuthTokenEncoded := "plktqQ%2BH9sENTTyYv%2B9jQ4BwSCEF2agtohyrSZWSo3o%3D"
	ctx := context.TODO()

	mocks.keycloakURIProvider.EXPECT().GetBaseURI(realmName).Return(keycloakBaseURI).AnyTimes()

	t.Run("Failed get trustIDAuthToken", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GenerateTrustIDAuthToken(accessToken, realmName, realmName, userID).Return("", errors.New("unexpected error"))
		_, err := onboarding.ComputeRedirectURI(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GenerateTrustIDAuthToken(accessToken, realmName, realmName, userID).Return(trustIDAuthToken, nil)
		uri, err := onboarding.ComputeRedirectURI(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI)
		assert.Nil(t, err)
		expectedURI := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/auth?client_id=%s&login_hint=%s&redirect_uri=%s&response_type=code&scope=openid&trustid_auth_token=%s", keycloakBaseURI, realmName, onboardingClientID, username, onboardingRedirectURIEncoded, trustIDAuthTokenEncoded)
		assert.Equal(t, expectedURI, uri)
	})
}

func TestCreateUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createOnboardingMocks(mockCtrl)
	onboarding := mocks.createOnboardingModule()

	realm := "cloudtrust"
	targetRealm := "client"
	ctx := context.Background()
	accessToken := "__TOKEN__"
	kcUser := kc.UserRepresentation{}

	t.Run("Can't generate username", func(t *testing.T) {
		errExistingUsername := errorhandler.Error{
			Status:  http.StatusConflict,
			Message: "keycloak.existing.username",
		}

		mocks.keycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), "generateNameID", "false").Return("", errExistingUsername).Times(10)
		_, err := onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser, false)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "username.generation")
	})
	t.Run("User creation fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), "generateNameID", "true").Return("", errors.New("any error"))
		_, err := onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser, true)
		assert.NotNil(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		userID := "12345678-abcd-9876"
		location := "http://location/users/" + userID
		kcUser.Username = nil

		mocks.keycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), "generateNameID", "false").Return(location, nil)

		resPath, err := onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser, false)
		assert.Nil(t, err)
		matched, errRegexp := regexp.Match(`^\d{8}$`, []byte(*kcUser.Username))
		assert.True(t, matched && errRegexp == nil)
		assert.Contains(t, resPath, *kcUser.ID)
	})
}

func TestProcessAlreadyExistingUserCases(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createOnboardingMocks(mockCtrl)
	onboarding := mocks.createOnboardingModule()

	ctx := context.TODO()
	accessToken := "access-token"
	targetRealmName := "target-realm"
	userID := "user-id"
	username := "12345678"
	userEmail := "user@email.com"
	realmRep := kc.RealmRepresentation{}
	usersPageRep := kc.UsersPageRepresentation{}
	createdTimestamp := time.Now().Unix()
	anyError := errors.New("any error")
	notSupposedToBeCalled := func(pUsername string, pCreatedTimestamp int64, pThirdParty *string) error {
		assert.Fail(t, "not supposed to be executed")
		return nil
	}
	var attrbs kc.Attributes = map[kc.AttributeKey][]string{}

	t.Run("Can't get realm from keycloak", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, targetRealmName).Return(realmRep, anyError)

		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.NotNil(t, err)
	})

	t.Run("Duplicate emails allowed", func(t *testing.T) {
		realmRep.DuplicateEmailsAllowed = ptrBool(true)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, targetRealmName).Return(realmRep, nil)

		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Nil(t, err)
	})

	realmRep.DuplicateEmailsAllowed = ptrBool(false)
	mocks.keycloakClient.EXPECT().GetRealm(accessToken, targetRealmName).Return(realmRep, nil).AnyTimes()

	t.Run("GetUsers fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, anyError)

		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.NotNil(t, err)
	})

	t.Run("No already existing user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil)

		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
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

		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.NotNil(t, err)
	})

	t.Run("User already exists-Already onboarded", func(t *testing.T) {
		attrbs[constants.AttrbOnboardingCompleted] = []string{"true"}
		usersPageRep.Users[0].Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil)

		errAlreadyOnboarded := errors.New("already onboarded")
		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, func(pUsername string, pCreatedTimestamp int64, pThirdParty *string) error {
			assert.Equal(t, username, pUsername)
			assert.Equal(t, createdTimestamp, pCreatedTimestamp)
			assert.Nil(t, pThirdParty)
			return errAlreadyOnboarded
		})
		assert.Equal(t, errAlreadyOnboarded, err)
	})

	t.Run("User already exists-Created by third party", func(t *testing.T) {
		thirdPartyName := "third-party-name"
		attrbs[constants.AttrbOnboardingCompleted] = []string{"false"}
		attrbs[constants.AttrbSource] = []string{thirdPartyName}
		usersPageRep.Users[0].Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", "="+userEmail).Return(usersPageRep, nil)

		errCreatedByThirdPart := errors.New("already onboarded")
		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, func(pUsername string, pCreatedTimestamp int64, pThirdParty *string) error {
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

		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Equal(t, anyError, err)
	})

	t.Run("User already exists-Successfully removed", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, userID).Return(nil)

		err := onboarding.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, userEmail, source, notSupposedToBeCalled)
		assert.Nil(t, err)
	})
}

func TestCanReplaceAccount(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createOnboardingMocks(mockCtrl)
	onboarding := mocks.createOnboardingModule()

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

func TestComputeOnboardingRedirectURI(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createOnboardingMocks(mockCtrl)
	onboarding := mocks.createOnboardingModule()

	ctx := context.Background()
	onboardingURI := "http://test.test?context=57a323d7-6da6-4c49-975e-4605ac8e101b"
	realmConf := configuration.RealmConfiguration{
		OnboardingRedirectURI: &onboardingURI,
	}

	t.Run("RealmConfiguration is null", func(t *testing.T) {
		_, err := onboarding.ComputeOnboardingRedirectURI(ctx, "target", "target", configuration.RealmConfiguration{})
		assert.NotNil(t, err)
	})

	t.Run("Success, target == customer", func(t *testing.T) {
		expectedURI := onboardingURI
		onboardingRedirectURI, err := onboarding.ComputeOnboardingRedirectURI(ctx, "target", "target", realmConf)
		assert.Nil(t, err)
		assert.Equal(t, expectedURI, onboardingRedirectURI)
	})

	t.Run("Success, target != customer", func(t *testing.T) {
		expectedURI := "http://test.test?context=57a323d7-6da6-4c49-975e-4605ac8e101b&customerRealm=customer"
		onboardingRedirectURI, err := onboarding.ComputeOnboardingRedirectURI(ctx, "target", "customer", realmConf)
		assert.Nil(t, err)
		assert.Equal(t, expectedURI, onboardingRedirectURI)
	})
}
