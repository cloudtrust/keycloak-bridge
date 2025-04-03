package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/fields"
	csjson "github.com/cloudtrust/common-service/v2/json"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"

	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	keycloakClient        *mock.KeycloakClient
	profileCache          *mock.UserProfileCache
	eventsReporter        *mock.AuditEventsReporterModule
	configurationDBModule *mock.ConfigurationDBModule
	onboardingModule      *mock.OnboardingModule
	authChecker           *mock.AuthorizationManager
	tokenProvider         *mock.OidcTokenProvider
	transaction           *mock.Transaction
	logger                *mock.Logger
	accreditationsClient  *mock.AccreditationsServiceClient
	producer              *mock.Producer
}

func createMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		keycloakClient:        mock.NewKeycloakClient(mockCtrl),
		profileCache:          mock.NewUserProfileCache(mockCtrl),
		eventsReporter:        mock.NewAuditEventsReporterModule(mockCtrl),
		configurationDBModule: mock.NewConfigurationDBModule(mockCtrl),
		onboardingModule:      mock.NewOnboardingModule(mockCtrl),
		authChecker:           mock.NewAuthorizationManager(mockCtrl),
		tokenProvider:         mock.NewOidcTokenProvider(mockCtrl),
		transaction:           mock.NewTransaction(mockCtrl),
		logger:                mock.NewLogger(mockCtrl),
		accreditationsClient:  mock.NewAccreditationsServiceClient(mockCtrl),
		producer:              mock.NewProducer(mockCtrl),
	}
}

var (
	allowedTrustIDGroups = []string{"grp1", "grp2"}
)

const (
	socialRealmName = "social"
)

func (m *componentMocks) createComponent() *component {
	/* REMOVE_THIS_3901 : remove second parameter (nil) */
	return NewComponent(m.keycloakClient, nil, m.profileCache, m.eventsReporter, m.configurationDBModule, m.onboardingModule, m.authChecker,
		m.tokenProvider, m.accreditationsClient, allowedTrustIDGroups, socialRealmName, m.logger, m.producer).(*component)
}

func ptrString(value string) *string {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}

func TestGetActions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	res, err := managementComponent.GetActions(ctx)
	assert.Nil(t, err)

	var checkPresence = func(action string, scope security.Scope) {
		s := string(scope)
		t.Run("Check "+action, func(t *testing.T) {
			assert.Contains(t, res, api.ActionRepresentation{Name: &action, Scope: &s})
		})
	}
	// Check presence of random actions
	checkPresence("MGMT_GetActions", security.ScopeGlobal)
	checkPresence("COM_SendEmail", security.ScopeRealm)
	checkPresence("COM_SendSMS", security.ScopeRealm)
	checkPresence("TSK_DeleteDeniedToUUsers", security.ScopeGlobal)
}

func TestGetRealms(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get realms with succces", func(t *testing.T) {
		var id = "1245"
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var kcRealmRep = kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		var kcRealmsRep []kc.RealmRepresentation
		kcRealmsRep = append(kcRealmsRep, kcRealmRep)

		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(kcRealmsRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRealmsRep, err := managementComponent.GetRealms(ctx)

		var expectedAPIRealmRep = api.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		var expectedAPIRealmsRep []api.RealmRepresentation
		expectedAPIRealmsRep = append(expectedAPIRealmsRep, expectedAPIRealmRep)

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIRealmsRep, apiRealmsRep)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return([]kc.RealmRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRealms(ctx)

		assert.NotNil(t, err)
	})
}

func TestGetRealm(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var username = "username"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get realm with succces", func(t *testing.T) {
		var id = "1245"
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var kcRealmRep = kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kcRealmRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		apiRealmRep, err := managementComponent.GetRealm(ctx, "master")

		var expectedAPIRealmRep = api.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIRealmRep, apiRealmRep)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRealm(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestGetClient(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get client with succces", func(t *testing.T) {
		var id = "1245-1245-4578"
		var name = "clientName"
		var baseURL = "http://toto.com"
		var clientID = "client-id"
		var protocol = "saml"
		var enabled = true
		var username = "username"

		var kcClientRep = kc.ClientRepresentation{
			ID:       &id,
			Name:     &name,
			BaseURL:  &baseURL,
			ClientID: &clientID,
			Protocol: &protocol,
			Enabled:  &enabled,
		}

		mocks.keycloakClient.EXPECT().GetClient(accessToken, realmName, id).Return(kcClientRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		apiClientRep, err := managementComponent.GetClient(ctx, "master", id)

		var expectedAPIClientRep = api.ClientRepresentation{
			ID:       &id,
			Name:     &name,
			BaseURL:  &baseURL,
			ClientID: &clientID,
			Protocol: &protocol,
			Enabled:  &enabled,
		}

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIClientRep, apiClientRep)
	})

	t.Run("Error", func(t *testing.T) {
		var id = "1234-79894-7594"
		mocks.keycloakClient.EXPECT().GetClient(accessToken, realmName, id).Return(kc.ClientRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClient(ctx, "master", id)

		assert.NotNil(t, err)
	})
}

func TestGetClients(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get clients with succces", func(t *testing.T) {
		var id = "1234-7894-58"
		var name = "clientName"
		var baseURL = "http://toto.com"
		var clientID = "client-id"
		var protocol = "saml"
		var enabled = true

		var kcClientRep = kc.ClientRepresentation{
			ID:       &id,
			Name:     &name,
			BaseURL:  &baseURL,
			ClientID: &clientID,
			Protocol: &protocol,
			Enabled:  &enabled,
		}

		var kcClientsRep []kc.ClientRepresentation
		kcClientsRep = append(kcClientsRep, kcClientRep)

		mocks.keycloakClient.EXPECT().GetClients(accessToken, realmName).Return(kcClientsRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiClientsRep, err := managementComponent.GetClients(ctx, "master")

		var expectedAPIClientRep = api.ClientRepresentation{
			ID:       &id,
			Name:     &name,
			BaseURL:  &baseURL,
			ClientID: &clientID,
			Protocol: &protocol,
			Enabled:  &enabled,
		}

		var expectedAPIClientsRep []api.ClientRepresentation
		expectedAPIClientsRep = append(expectedAPIClientsRep, expectedAPIClientRep)

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIClientsRep, apiClientsRep)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetClients(accessToken, realmName).Return([]kc.ClientRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClients(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestGetRequiredActions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get required actions with succces", func(t *testing.T) {
		var alias = "ALIAS"
		var name = "name"
		var boolTrue = true
		var boolFalse = false

		var kcRa = kc.RequiredActionProviderRepresentation{
			Alias:         &alias,
			Name:          &name,
			Enabled:       &boolTrue,
			DefaultAction: &boolTrue,
		}

		var kcDisabledRa = kc.RequiredActionProviderRepresentation{
			Alias:         &alias,
			Name:          &name,
			Enabled:       &boolFalse,
			DefaultAction: &boolFalse,
		}

		var kcRasRep []kc.RequiredActionProviderRepresentation
		kcRasRep = append(kcRasRep, kcRa, kcDisabledRa)

		mocks.keycloakClient.EXPECT().GetRequiredActions(accessToken, realmName).Return(kcRasRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRasRep, err := managementComponent.GetRequiredActions(ctx, "master")

		var expectedAPIRaRep = api.RequiredActionRepresentation{
			Alias:         &alias,
			Name:          &name,
			DefaultAction: &boolTrue,
		}

		var expectedAPIRasRep []api.RequiredActionRepresentation
		expectedAPIRasRep = append(expectedAPIRasRep, expectedAPIRaRep)

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIRasRep, apiRasRep)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRequiredActions(accessToken, realmName).Return([]kc.RequiredActionProviderRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRequiredActions(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestCreateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var username = "test"
	var realmName = "master"
	var targetRealmName = "DEP"
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var locationURL = "http://toto.com/realms/" + userID
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Create user failed - can't retrieve admin configuration", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, socialRealmName).Return(configuration.RealmAdminConfiguration{}, anyError)
		mocks.logger.EXPECT().Warn(ctx, "msg", "Failed to retrieve realm admin configuration", "err", anyError.Error())

		_, err := managementComponent.CreateUser(ctx, socialRealmName, api.UserRepresentation{}, false, false, false)

		assert.Equal(t, anyError, err)
	})

	t.Run("Create user with username generation, don't need terms of use", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, socialRealmName).Return(configuration.RealmAdminConfiguration{
			OnboardingStatusEnabled: ptrBool(false),
		}, nil)
		mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, realmName, socialRealmName, gomock.Any(), false).
			DoAndReturn(func(_, _, _, _ interface{}, user *kc.UserRepresentation, _ interface{}) (string, error) {
				assert.NotNil(t, user)
				assert.Nil(t, user.RequiredActions)
				return "", anyError
			})
		mocks.logger.EXPECT().Warn(ctx, "err", gomock.Any())

		_, err := managementComponent.CreateUser(ctx, socialRealmName, api.UserRepresentation{}, false, false, false)

		assert.Equal(t, anyError, err)
	})
	t.Run("Create user with username generation, need terms of use", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, socialRealmName).Return(configuration.RealmAdminConfiguration{
			OnboardingStatusEnabled: ptrBool(false),
		}, nil)
		mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, realmName, socialRealmName, gomock.Any(), true).
			DoAndReturn(func(_, _, _, _ interface{}, user *kc.UserRepresentation, _ interface{}) (string, error) {
				assert.NotNil(t, user)
				assert.NotNil(t, user.RequiredActions)
				assert.Len(t, *user.RequiredActions, 1)
				assert.Equal(t, (*user.RequiredActions)[0], "ct-terms-of-use")
				return "", anyError
			})
		mocks.logger.EXPECT().Warn(ctx, "err", gomock.Any())

		_, err := managementComponent.CreateUser(ctx, socialRealmName, api.UserRepresentation{}, false, true, true)

		assert.Equal(t, anyError, err)
	})

	var attrbs = make(kc.Attributes)
	attrbs[constants.AttrbSource] = []string{"api"}

	t.Run("Create with minimum properties", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrbs,
		}

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, targetRealmName).Return(configuration.RealmAdminConfiguration{
			OnboardingStatusEnabled: ptrBool(false),
		}, nil)
		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, kcUserRep, "generateNameID", "false").Return(locationURL, nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		var userRep = api.UserRepresentation{
			Username: &username,
		}

		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, false, false)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	attrbs[constants.AttrbOnboardingStatus] = []string{"user-created-by-api"}

	t.Run("Create with all properties allowed by Bridge API", func(t *testing.T) {
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var phoneNumber = "+41789456"
		var phoneNumberVerified = true
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"
		var locale = "de"

		var groups = []string{"145-784-545251"}
		var trustIDGroups = []string{"l1_support_agent"}
		var roles = []string{"445-4545-751515"}

		var birthLocation = "Rolle"
		var nationality = "CH"
		var idDocumentType = "Card ID"
		var idDocumentNumber = "1234-4567-VD-3"
		var idDocumentExpiration = "23.12.2019"
		var idDocumentCountry = "IT"

		var onboardingStatus = "user-created-by-api"

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, targetRealmName).Return(configuration.RealmAdminConfiguration{
			OnboardingStatusEnabled: ptrBool(true),
		}, nil)
		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(accessToken, realmName, targetRealmName string, kcUserRep kc.UserRepresentation, _ ...interface{}) (string, error) {
				assert.Equal(t, username, *kcUserRep.Username)
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, enabled, *kcUserRep.Enabled)
				assert.Equal(t, emailVerified, *kcUserRep.EmailVerified)
				assert.Equal(t, firstName, *kcUserRep.FirstName)
				assert.Equal(t, lastName, *kcUserRep.LastName)
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, phoneNumberVerified, *verified)
				assert.Equal(t, label, *kcUserRep.GetAttributeString(constants.AttrbLabel))
				assert.Equal(t, gender, *kcUserRep.GetAttributeString(constants.AttrbGender))
				assert.Equal(t, birthDate, *kcUserRep.GetAttributeString(constants.AttrbBirthDate))
				assert.Equal(t, locale, *kcUserRep.GetAttributeString(constants.AttrbLocale))
				assert.Equal(t, onboardingStatus, *kcUserRep.GetAttributeString(constants.AttrbOnboardingStatus))
				return locationURL, nil
			})

		var userRep = api.UserRepresentation{
			ID:                   &userID,
			Username:             &username,
			Email:                &email,
			Enabled:              &enabled,
			EmailVerified:        &emailVerified,
			FirstName:            &firstName,
			LastName:             &lastName,
			PhoneNumber:          &phoneNumber,
			PhoneNumberVerified:  &phoneNumberVerified,
			Label:                &label,
			Gender:               &gender,
			BirthDate:            &birthDate,
			Locale:               &locale,
			Groups:               &groups,
			TrustIDGroups:        &trustIDGroups,
			Roles:                &roles,
			BirthLocation:        &birthLocation,
			Nationality:          &nationality,
			IDDocumentType:       &idDocumentType,
			IDDocumentNumber:     &idDocumentNumber,
			IDDocumentExpiration: &idDocumentExpiration,
			IDDocumentCountry:    &idDocumentCountry,
		}
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, true, false)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			Attributes: &attrbs,
		}

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, targetRealmName).Return(configuration.RealmAdminConfiguration{
			OnboardingStatusEnabled: ptrBool(true),
		}, nil)
		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, kcUserRep, "generateNameID", "false").Return("", fmt.Errorf("Invalid input"))

		var userRep = api.UserRepresentation{}
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, false, false)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	})
}

func TestCreateUserInSocialRealm(t *testing.T) {
	// Only test branches not reached by TestCreateUserInSocialRealm
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var username = "test"
	var realmName = "my-realm"
	var email = "user@domain.com"
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	var userRep = api.UserRepresentation{
		Email: &email,
	}
	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()
	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Can't get JWT token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)

		_, err := managementComponent.CreateUserInSocialRealm(ctx, userRep, false)
		assert.Equal(t, anyError, err)
	})
	t.Run("Process already existing user cases calls handler", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, socialRealmName).Return(configuration.RealmAdminConfiguration{}, nil)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(ctx, accessToken, managementComponent.socialRealmName, email, realmName, gomock.Any()).Return(anyError)
		_, err := managementComponent.CreateUserInSocialRealm(ctx, userRep, false)
		assert.Equal(t, anyError, err)
	})
	t.Run("onAlreadyExistsUser", func(t *testing.T) {
		var err = managementComponent.onAlreadyExistsUser("", 0, ptr(""))
		assert.IsType(t, errorhandler.Error{}, err)
		var errWithDetails = err.(errorhandler.Error)
		assert.Equal(t, http.StatusConflict, errWithDetails.Status)
	})
}

func TestDeleteUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var realmName = "master"
	var username = "username"

	t.Run("Delete user with success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		err := managementComponent.DeleteUser(ctx, "master", userID)

		assert.Nil(t, err)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		err := managementComponent.DeleteUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestGetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var id = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var username = "username"

	t.Run("Get user with succces", func(t *testing.T) {
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var phoneNumber = "+41789456"
		var phoneNumberVerified = true
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"
		var nationality = "AU"
		var now = time.Now().UTC()
		var createdTimestamp = now.Unix()
		var locale = "it"
		var trustIDGroups = []string{"grp1", "grp2"}
		var birthLocation = "Rolle"
		var idDocumentType = "Card ID"
		var idDocumentNumber = "1234-4567-VD-3"
		var idDocumentExpiration = "23.12.2019"
		var idDocumentCountry = "MX"
		var onboardingStatus = "user-created-by-api"

		var attributes = make(kc.Attributes)
		attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
		attributes.SetString(constants.AttrbLabel, label)
		attributes.SetString(constants.AttrbGender, gender)
		attributes.SetString(constants.AttrbBirthDate, birthDate)
		attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
		attributes.SetString(constants.AttrbLocale, locale)
		attributes.Set(constants.AttrbTrustIDGroups, trustIDGroups)
		attributes.SetString(constants.AttrbBirthLocation, birthLocation)
		attributes.SetString(constants.AttrbNationality, nationality)
		attributes.SetString(constants.AttrbIDDocumentType, idDocumentType)
		attributes.SetString(constants.AttrbIDDocumentNumber, idDocumentNumber)
		attributes.SetString(constants.AttrbIDDocumentExpiration, idDocumentExpiration)
		attributes.SetString(constants.AttrbIDDocumentCountry, idDocumentCountry)
		attributes.SetString(constants.AttrbOnboardingStatus, onboardingStatus)

		var kcUserRep = kc.UserRepresentation{
			ID:               &id,
			Username:         &username,
			Email:            &email,
			Enabled:          &enabled,
			EmailVerified:    &emailVerified,
			FirstName:        &firstName,
			LastName:         &lastName,
			Attributes:       &attributes,
			CreatedTimestamp: &createdTimestamp,
		}

		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUserID, id)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]accreditationsclient.CheckRepresentation{{
			Nature:   ptr("nature"),
			Status:   ptr("PENDING"),
			DateTime: &now,
		}}, nil)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		apiUserRep, err := managementComponent.GetUser(ctx, "master", id)

		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, enabled, *apiUserRep.Enabled)
		assert.Equal(t, emailVerified, *apiUserRep.EmailVerified)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, phoneNumber, *apiUserRep.PhoneNumber)
		assert.Equal(t, phoneNumberVerified, *apiUserRep.PhoneNumberVerified)
		assert.Equal(t, label, *apiUserRep.Label)
		assert.Equal(t, gender, *apiUserRep.Gender)
		assert.Equal(t, birthDate, *apiUserRep.BirthDate)
		assert.Equal(t, createdTimestamp, *apiUserRep.CreatedTimestamp)
		assert.Equal(t, locale, *apiUserRep.Locale)
		assert.Equal(t, trustIDGroups, *apiUserRep.TrustIDGroups)
		assert.Equal(t, birthLocation, *apiUserRep.BirthLocation)
		assert.Equal(t, nationality, *apiUserRep.Nationality)
		assert.Equal(t, idDocumentExpiration, *apiUserRep.IDDocumentExpiration)
		assert.Equal(t, idDocumentNumber, *apiUserRep.IDDocumentNumber)
		assert.Equal(t, idDocumentType, *apiUserRep.IDDocumentType)
		assert.Equal(t, idDocumentCountry, *apiUserRep.IDDocumentCountry)
		assert.Equal(t, onboardingStatus, *apiUserRep.OnboardingStatus)
	})

	t.Run("Get user with succces with empty user info", func(t *testing.T) {
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var phoneNumber = "+41789456"
		var phoneNumberVerified = true
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"
		var now = time.Now().UTC()
		var createdTimestamp = now.Unix()
		var locale = "it"
		var trustIDGroups = []string{"grp1", "grp2"}

		var attributes = make(kc.Attributes)
		attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
		attributes.SetString(constants.AttrbLabel, label)
		attributes.SetString(constants.AttrbGender, gender)
		attributes.SetString(constants.AttrbBirthDate, birthDate)
		attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
		attributes.SetString(constants.AttrbLocale, locale)
		attributes.Set(constants.AttrbTrustIDGroups, trustIDGroups)

		var kcUserRep = kc.UserRepresentation{
			ID:               &id,
			Username:         &username,
			Email:            &email,
			Enabled:          &enabled,
			EmailVerified:    &emailVerified,
			FirstName:        &firstName,
			LastName:         &lastName,
			Attributes:       &attributes,
			CreatedTimestamp: &createdTimestamp,
		}

		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUserID, id)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]accreditationsclient.CheckRepresentation{{
			Nature:   ptr("nature"),
			Status:   ptr("PENDING"),
			DateTime: &now,
		}}, nil)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		apiUserRep, err := managementComponent.GetUser(ctx, "master", id)

		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, enabled, *apiUserRep.Enabled)
		assert.Equal(t, emailVerified, *apiUserRep.EmailVerified)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, phoneNumber, *apiUserRep.PhoneNumber)
		assert.Equal(t, phoneNumberVerified, *apiUserRep.PhoneNumberVerified)
		assert.Equal(t, label, *apiUserRep.Label)
		assert.Equal(t, gender, *apiUserRep.Gender)
		assert.Equal(t, birthDate, *apiUserRep.BirthDate)
		assert.Equal(t, createdTimestamp, *apiUserRep.CreatedTimestamp)
		assert.Equal(t, locale, *apiUserRep.Locale)
		assert.Equal(t, trustIDGroups, *apiUserRep.TrustIDGroups)
		assert.Nil(t, apiUserRep.BirthLocation)
		assert.Nil(t, apiUserRep.Nationality)
		assert.Nil(t, apiUserRep.IDDocumentExpiration)
		assert.Nil(t, apiUserRep.IDDocumentNumber)
		assert.Nil(t, apiUserRep.IDDocumentType)
		assert.Nil(t, apiUserRep.IDDocumentCountry)
		assert.Nil(t, apiUserRep.OnboardingStatus)
	})

	t.Run("Retrieve checks fails", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			ID:       &id,
			Username: &username,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]accreditationsclient.CheckRepresentation{}, fmt.Errorf("SQL Error"))
		mocks.logger.EXPECT().Warn(ctx, "msg", "Can't get pending checks", "err", "SQL Error")

		_, err := managementComponent.GetUser(ctx, "master", id)

		assert.NotNil(t, err)
	})

	t.Run("Error with KC", func(t *testing.T) {
		var id = "1234-79894-7594"
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")

		_, err := managementComponent.GetUser(ctx, "master", id)

		assert.NotNil(t, err)
	})
}

func createUpdateUser() api.UpdatableUserRepresentation {
	var username = "username"
	var email = "toto@elca.ch"
	var emailVerified = true
	var firstName = "Titi"
	var lastName = "Tutu"
	var phoneNumber = "+41789456"
	var phoneNumberVerified = true
	var label = "Label"
	var gender = "M"
	var birthDate = "01/01/1988"
	var locale = "de"

	return api.UpdatableUserRepresentation{
		Username:            &username,
		Email:               csjson.StringToOptional(email),
		EmailVerified:       &emailVerified,
		FirstName:           &firstName,
		LastName:            &lastName,
		PhoneNumber:         csjson.StringToOptional(phoneNumber),
		PhoneNumberVerified: &phoneNumberVerified,
		Label:               &label,
		Gender:              &gender,
		BirthDate:           &birthDate,
		Locale:              &locale,
	}
}

func TestUpdateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var (
		accessToken = "TOKEN=="
		realmName   = "master"
		id          = "41dbf4a8-32a9-4000-8c17-edc854c31231"
		enabled     = true
		disabled    = false

		birthLocation        = "Rolle"
		nationality          = "CH"
		idDocumentType       = "Card ID"
		idDocumentNumber     = "1234-4567-VD-3"
		idDocumentExpiration = "23.12.2019"
		idDocumentCountry    = "CH"
		createdTimestamp     = time.Now().UTC().Unix()
		anyError             = errors.New("any error")
		userRep              = createUpdateUser()
	)

	var attributes = make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, *userRep.PhoneNumber.Value)
	attributes.SetString(constants.AttrbLabel, *userRep.Label)
	attributes.SetString(constants.AttrbGender, *userRep.Gender)
	attributes.SetString(constants.AttrbBirthDate, *userRep.BirthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
	attributes.SetString(constants.AttrbLocale, *userRep.Locale)
	attributes.SetString(constants.AttrbBirthLocation, birthLocation)
	attributes.SetString(constants.AttrbNationality, nationality)
	attributes.SetString(constants.AttrbIDDocumentType, idDocumentType)
	attributes.SetString(constants.AttrbIDDocumentNumber, idDocumentNumber)
	attributes.SetString(constants.AttrbIDDocumentExpiration, idDocumentExpiration)
	attributes.SetString(constants.AttrbIDDocumentCountry, idDocumentCountry)

	var kcUserRep = kc.UserRepresentation{
		ID:               &id,
		Username:         userRep.Username,
		Email:            userRep.Email.Value,
		Enabled:          &enabled,
		EmailVerified:    userRep.EmailVerified,
		FirstName:        userRep.FirstName,
		LastName:         userRep.LastName,
		Attributes:       &attributes,
		CreatedTimestamp: &createdTimestamp,
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUserID, id)
	ctx = context.WithValue(ctx, cs.CtContextUsername, *userRep.Username)

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Accreditations evaluation fails", func(t *testing.T) {
		var newUsername = "new-username"
		var userWithNewUsername = createUpdateUser()
		userWithNewUsername.Username = &newUsername

		mocks.keycloakClient.EXPECT().GetUser(accessToken, socialRealmName, id).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, anyError)
		mocks.logger.EXPECT().Warn(ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, socialRealmName, id, userWithNewUsername)

		assert.Equal(t, anyError, err)
	})

	t.Run("Update user in realm with self register enabled", func(t *testing.T) {
		var newUsername = "new-username"
		var userWithNewUsername = createUpdateUser()
		userWithNewUsername.Username = &newUsername

		mocks.keycloakClient.EXPECT().GetUser(accessToken, socialRealmName, id).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, socialRealmName, id, gomock.Any()).DoAndReturn(func(_, _, _ interface{}, updUser kc.UserRepresentation) error {
			assert.NotEqual(t, userWithNewUsername.Username, updUser.Username)
			assert.Equal(t, userRep.Username, updUser.Username)
			return anyError
		})
		mocks.logger.EXPECT().Warn(ctx, gomock.Any())

		err := managementComponent.UpdateUser(ctx, socialRealmName, id, userWithNewUsername)

		assert.Equal(t, anyError, err)
	})
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(gomock.Any(), gomock.Any()).Return(configuration.RealmAdminConfiguration{SelfRegisterEnabled: ptrBool(false)}, nil).AnyTimes()

	t.Run("Update user with succces (without user info update)", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, *userRep.Username, *kcUserRep.Username)
				assert.Equal(t, *userRep.Email.Value, *kcUserRep.Email)
				assert.Equal(t, *userRep.EmailVerified, *kcUserRep.EmailVerified)
				assert.Equal(t, *userRep.FirstName, *kcUserRep.FirstName)
				assert.Equal(t, *userRep.LastName, *kcUserRep.LastName)
				assert.Equal(t, *userRep.PhoneNumber.Value, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, *userRep.PhoneNumberVerified, *verified)
				assert.Equal(t, *userRep.Label, *kcUserRep.GetAttributeString(constants.AttrbLabel))
				assert.Equal(t, *userRep.Gender, *kcUserRep.GetAttributeString(constants.AttrbGender))
				assert.Equal(t, *userRep.BirthDate, *kcUserRep.GetAttributeString(constants.AttrbBirthDate))
				assert.Equal(t, *userRep.Locale, *kcUserRep.GetAttributeString(constants.AttrbLocale))
				return nil
			})

		err := managementComponent.UpdateUser(ctx, realmName, id, userRep)

		assert.Nil(t, err)
	})

	t.Run("Update user with succces (with user info update)", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil).Times(2)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil).Times(2)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, *userRep.Username, *kcUserRep.Username)
				assert.Equal(t, *userRep.Email.Value, *kcUserRep.Email)
				assert.Equal(t, *userRep.EmailVerified, *kcUserRep.EmailVerified)
				assert.Equal(t, *userRep.FirstName, *kcUserRep.FirstName)
				assert.Equal(t, *userRep.LastName, *kcUserRep.LastName)
				assert.Equal(t, *userRep.PhoneNumber.Value, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, *userRep.PhoneNumberVerified, *verified)
				assert.Equal(t, *userRep.Label, *kcUserRep.GetAttributeString(constants.AttrbLabel))
				assert.Equal(t, *userRep.Gender, *kcUserRep.GetAttributeString(constants.AttrbGender))
				assert.Equal(t, *userRep.BirthDate, *kcUserRep.GetAttributeString(constants.AttrbBirthDate))
				assert.Equal(t, *userRep.Locale, *kcUserRep.GetAttributeString(constants.AttrbLocale))
				return nil
			}).Times(2)

		newIDDocumentExpiration := "21.12.2030"
		var userAPI = createUpdateUser()
		userAPI.IDDocumentExpiration = &newIDDocumentExpiration

		err := managementComponent.UpdateUser(ctx, realmName, id, userAPI)
		assert.Nil(t, err)

		newBirthLocation := "21.12.1988"
		newNationality := "NO"
		newIDDocumentType := "Permit"
		newIDDocumentNumber := "123456frs"
		newIDDocumentCountry := "PT"
		userAPI.BirthLocation = &newBirthLocation
		userAPI.Nationality = &newNationality
		userAPI.IDDocumentType = &newIDDocumentType
		userAPI.IDDocumentNumber = &newIDDocumentNumber
		userAPI.IDDocumentCountry = &newIDDocumentCountry

		err = managementComponent.UpdateUser(ctx, realmName, id, userAPI)
		assert.Nil(t, err)
	})

	t.Run("Update by locking the user", func(t *testing.T) {
		kcUserRep.Enabled = &enabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, *userRep.Username, *kcUserRep.Username)
				assert.Equal(t, *userRep.Email.Value, *kcUserRep.Email)
				assert.Equal(t, disabled, *kcUserRep.Enabled)
				assert.Equal(t, *userRep.EmailVerified, *kcUserRep.EmailVerified)
				assert.Equal(t, *userRep.FirstName, *kcUserRep.FirstName)
				assert.Equal(t, *userRep.LastName, *kcUserRep.LastName)
				assert.Equal(t, *userRep.PhoneNumber.Value, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, *userRep.PhoneNumberVerified, *verified)
				assert.Equal(t, *userRep.Label, *kcUserRep.GetAttributeString(constants.AttrbLabel))
				assert.Equal(t, *userRep.Gender, *kcUserRep.GetAttributeString(constants.AttrbGender))
				assert.Equal(t, *userRep.BirthDate, *kcUserRep.GetAttributeString(constants.AttrbBirthDate))
				assert.Equal(t, *userRep.Locale, *kcUserRep.GetAttributeString(constants.AttrbLocale))
				return nil
			})

		var userRepLocked = createUpdateUser()
		userRepLocked.Enabled = &disabled

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, "master", id, userRepLocked)

		assert.Nil(t, err)
	})

	t.Run("Update to unlock the user", func(t *testing.T) {
		kcUserRep.Enabled = &disabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).Return(nil)

		var userRepLocked = createUpdateUser()
		userRepLocked.Enabled = &enabled

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, "master", id, userRepLocked)

		assert.Nil(t, err)
	})

	t.Run("Update by changing the email address", func(t *testing.T) {
		var oldEmail = "toti@elca.ch"
		var oldkcUserRep = kc.UserRepresentation{
			ID:            &id,
			Email:         &oldEmail,
			EmailVerified: userRep.EmailVerified,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(oldkcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, oldEmail, *kcUserRep.Email)
				assert.Equal(t, *userRep.Email.Value, *kcUserRep.GetAttributeString("emailToValidate"))
				return nil
			})
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, "master", id, userRep)

		assert.Nil(t, err)
	})

	t.Run("Update by removing the email address", func(t *testing.T) {
		var oldEmail = "toti@elca.ch"
		var oldkcUserRep = kc.UserRepresentation{
			ID:            &id,
			Email:         &oldEmail,
			EmailVerified: userRep.EmailVerified,
		}
		var withoutEmailUser = createUpdateUser()
		withoutEmailUser.Email = csjson.OptionalString{Defined: true, Value: nil}
		withoutEmailUser.PhoneNumber.Defined = false
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(oldkcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, "", *kcUserRep.Email)
				assert.Equal(t, false, *kcUserRep.EmailVerified)
				assert.Nil(t, kcUserRep.GetFieldValues(fields.Accreditations))
				return nil
			})
		// No execute action email is sent for phoneNumber change as there is no current phoneNumber defined

		err := managementComponent.UpdateUser(ctx, "master", id, withoutEmailUser)

		assert.Nil(t, err)
	})

	t.Run("Update by changing the phone number", func(t *testing.T) {
		var oldNumber = "+41789467"
		var oldAttributes = make(kc.Attributes)
		oldAttributes.SetString(constants.AttrbPhoneNumber, oldNumber)
		oldAttributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
		var oldkcUserRep2 = kc.UserRepresentation{
			ID:         &id,
			Attributes: &oldAttributes,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(oldkcUserRep2, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, oldNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, *userRep.PhoneNumber.Value, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumberToValidate))
				assert.Equal(t, true, *verified)
				return nil
			})
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, "master", id, userRep)

		assert.Nil(t, err)
	})

	t.Run("Update by removing the phone number", func(t *testing.T) {
		var oldNumber = "+41789467"
		var oldAttributes = make(kc.Attributes)
		oldAttributes.SetString(constants.AttrbPhoneNumber, oldNumber)
		oldAttributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
		var oldkcUserRep2 = kc.UserRepresentation{
			ID:         &id,
			Attributes: &oldAttributes,
		}
		var withoutPhoneNumberUser = userRep
		withoutPhoneNumberUser.PhoneNumber = csjson.OptionalString{Defined: true, Value: nil}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(oldkcUserRep2, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				_, ok := (*kcUserRep.Attributes)[constants.AttrbPhoneNumber]
				assert.False(t, ok)
				_, ok = (*kcUserRep.Attributes)[constants.AttrbPhoneNumberVerified]
				assert.False(t, ok)
				return nil
			})
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, "master", id, withoutPhoneNumberUser)

		assert.Nil(t, err)
	})

	t.Run("Update without attributes", func(t *testing.T) {
		var userRepWithoutAttr = api.UpdatableUserRepresentation{
			Username:  userRep.Username,
			Email:     userRep.Email,
			FirstName: userRep.FirstName,
			LastName:  userRep.LastName,
		}

		var oldNumber = "+41789467"
		var oldAttributes = make(kc.Attributes)
		oldAttributes.SetString(constants.AttrbPhoneNumber, oldNumber)
		oldAttributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
		var oldkcUserRep2 = kc.UserRepresentation{
			ID:         &id,
			Attributes: &oldAttributes,
		}

		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(oldkcUserRep2, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, oldNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, true, *verified)
				return nil
			})
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, "master", id, userRepWithoutAttr)

		assert.Nil(t, err)
	})

	t.Run("Error - get user KC", func(t *testing.T) {
		var id = "1234-79894-7594"
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateUser(ctx, "master", id, api.UpdatableUserRepresentation{})

		assert.NotNil(t, err)
	})

	t.Run("Error - update user KC", func(t *testing.T) {
		var id = "1234-79894-7594"
		var kcUserRep = kc.UserRepresentation{
			ID: &id,
		}
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil).AnyTimes()
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).Return(fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Unexpected error")

		err := managementComponent.UpdateUser(ctx, "master", id, api.UpdatableUserRepresentation{})

		assert.NotNil(t, err)
	})
}

func TestIsEmailVerified(t *testing.T) {
	assert.False(t, isEmailVerified(kc.UserRepresentation{EmailVerified: nil}))
	assert.False(t, isEmailVerified(kc.UserRepresentation{EmailVerified: ptrBool(false)}))
	assert.True(t, isEmailVerified(kc.UserRepresentation{EmailVerified: ptrBool(true)}))
}

func TestIsPhoneNumberVerified(t *testing.T) {
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{}))
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{}}))
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: nil}}))
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: []string{}}}))
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: []string{""}}}))
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: []string{"", "true"}}}))
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: []string{"false", "true"}}}))
	assert.True(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: []string{"true", "false"}}}))
	assert.False(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: []string{"false"}}}))
	assert.True(t, isPhoneNumberVerified(kc.UserRepresentation{Attributes: &kc.Attributes{constants.AttrbPhoneNumberVerified: []string{"true"}}}))
}

func TestLockUnlockUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "myrealm"
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var anyError = errors.New("any")
	var bTrue = true
	var bFalse = false
	var ctx = context.TODO()
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetUser fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, anyError)
		var err = managementComponent.LockUser(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Can't lock disabled user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bFalse}, nil)
		var err = managementComponent.LockUser(ctx, realmName, userID)
		assert.Nil(t, err)
	})
	t.Run("UpdateUser fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bFalse}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(anyError)
		var err = managementComponent.UnlockUser(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Lock success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bTrue}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		var err = managementComponent.LockUser(ctx, realmName, userID)
		assert.Nil(t, err)
	})
	t.Run("Unlock success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bFalse}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		var err = managementComponent.UnlockUser(ctx, realmName, userID)
		assert.Nil(t, err)
	})
}

func TestGetUsers(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var targetRealmName = "DEP"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get user with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var username = "username"
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var phoneNumber = "+41789456"
		var phoneNumberVerified = true
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"
		var createdTimestamp = time.Now().UTC().Unix()

		var attributes = make(kc.Attributes)
		attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
		attributes.SetString(constants.AttrbLabel, label)
		attributes.SetString(constants.AttrbGender, gender)
		attributes.SetString(constants.AttrbBirthDate, birthDate)
		attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)

		var count = 10
		var kcUserRep = kc.UserRepresentation{
			ID:               &id,
			Username:         &username,
			Email:            &email,
			Enabled:          &enabled,
			EmailVerified:    &emailVerified,
			FirstName:        &firstName,
			LastName:         &lastName,
			Attributes:       &attributes,
			CreatedTimestamp: &createdTimestamp,
		}
		var kcUsersRep = kc.UsersPageRepresentation{
			Count: &count,
			Users: []kc.UserRepresentation{kcUserRep},
		}

		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmName, targetRealmName, "groupId", "123-456-789").Return(kcUsersRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextUserID, id)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		apiUsersRep, err := managementComponent.GetUsers(ctx, "DEP", []string{"123-456-789"})

		var apiUserRep = apiUsersRep.Users[0]
		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, enabled, *apiUserRep.Enabled)
		assert.Equal(t, emailVerified, *apiUserRep.EmailVerified)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, phoneNumber, *apiUserRep.PhoneNumber)
		verified, _ := strconv.ParseBool(((*kcUserRep.Attributes)["phoneNumberVerified"][0]))
		assert.Equal(t, phoneNumberVerified, verified)
		assert.Equal(t, label, *apiUserRep.Label)
		assert.Equal(t, gender, *apiUserRep.Gender)
		assert.Equal(t, birthDate, *apiUserRep.BirthDate)
		assert.Equal(t, createdTimestamp, *apiUserRep.CreatedTimestamp)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmName, targetRealmName, "groupId", "123-456-789").Return(kc.UsersPageRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		_, err := managementComponent.GetUsers(ctx, "DEP", []string{"123-456-789"})

		assert.NotNil(t, err)
	})
}

func TestGetUserChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "aRealm"
	var userID = "789-789-456"
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetChecks returns an error", func(t *testing.T) {
		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realmName, userID).Return(nil, errors.New("db error"))
		_, err := managementComponent.GetUserChecks(ctx, realmName, userID)
		assert.NotNil(t, err)
	})
	t.Run("GetChecks returns a check", func(t *testing.T) {
		var operator = "The Operator"
		var dbCheck = accreditationsclient.CheckRepresentation{
			Operator: &operator,
		}
		var dbChecks = []accreditationsclient.CheckRepresentation{dbCheck, dbCheck}
		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realmName, userID).Return(dbChecks, nil)
		res, err := managementComponent.GetUserChecks(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Len(t, res, len(dbChecks))
		assert.Equal(t, operator, *res[0].Operator)
	})
}

func TestGetUserAccountStatus(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmReq = "master"
	var realmName = "aRealm"
	var userID = "789-789-456"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetUser returns an error", func(t *testing.T) {
		var userRep kc.UserRepresentation
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(userRep, fmt.Errorf("Unexpected error"))
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		_, err := managementComponent.GetUserAccountStatus(ctx, realmName, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUser returns a non-enabled user", func(t *testing.T) {
		var userRep kc.UserRepresentation
		enabled := false
		userRep.Enabled = &enabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(userRep, nil)
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		status, err := managementComponent.GetUserAccountStatus(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.False(t, status["enabled"])
	})

	t.Run("GetUser returns an enabled user but GetCredentialsForUser fails", func(t *testing.T) {
		var userRep kc.UserRepresentation
		enabled := true
		userRep.Enabled = &enabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(userRep, nil)
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return(nil, fmt.Errorf("Unexpected error"))
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)
		_, err := managementComponent.GetUserAccountStatus(ctx, realmName, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUser returns an enabled user but GetCredentialsForUser have no credential", func(t *testing.T) {
		var userRep kc.UserRepresentation
		enabled := true
		userRep.Enabled = &enabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(userRep, nil)
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{}, nil)
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)
		status, err := managementComponent.GetUserAccountStatus(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.False(t, status["enabled"])
	})

	t.Run("GetUser returns an enabled user and GetCredentialsForUser have credentials", func(t *testing.T) {
		var userRep kc.UserRepresentation
		var creds1, creds2 kc.CredentialRepresentation
		enabled := true
		userRep.Enabled = &enabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(userRep, nil)
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{creds1, creds2}, nil)
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)
		status, err := managementComponent.GetUserAccountStatus(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.True(t, status["enabled"])
	})
}

func TestGetUserAccountStatusByEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmReq = "master"
	var realmName = "aRealm"
	var userID = "1234-abcd-5678"
	var email = "user@domain.ch"
	var anyError = errors.New("any error")
	var searchedUser = kc.UserRepresentation{
		ID:      &userID,
		Email:   &email,
		Enabled: ptrBool(true),
		Attributes: &kc.Attributes{
			constants.AttrbPhoneNumberVerified: []string{"true"},
			constants.AttrbOnboardingCompleted: []string{"true"},
		},
	}
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetUser returns an error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmReq, realmName, "email", "="+email).Return(kc.UsersPageRepresentation{}, anyError)

		_, err := managementComponent.GetUserAccountStatusByEmail(ctx, realmName, email)

		assert.Equal(t, anyError, err)
	})
	t.Run("No user found", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmReq, realmName, "email", "="+email).Return(kc.UsersPageRepresentation{}, nil)

		_, err := managementComponent.GetUserAccountStatusByEmail(ctx, realmName, email)

		assert.NotNil(t, err)
	})
	t.Run("Found users does not match exactly the given email", func(t *testing.T) {
		var users = []kc.UserRepresentation{{}, {}, {}}
		var count = len(users)
		users[0].Email = nil
		users[1].Email = ptrString("a" + email)
		users[2].Email = ptrString("b" + email)
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmReq, realmName, "email", "="+email).Return(kc.UsersPageRepresentation{
			Count: &count,
			Users: users,
		}, nil)

		_, err := managementComponent.GetUserAccountStatusByEmail(ctx, realmName, email)

		assert.NotNil(t, err)
	})
	t.Run("Found too many users", func(t *testing.T) {
		var user1 = kc.UserRepresentation{Email: &email}
		var users = []kc.UserRepresentation{user1, user1, user1}
		var count = len(users)
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmReq, realmName, "email", "="+email).Return(kc.UsersPageRepresentation{
			Count: &count,
			Users: users,
		}, nil)

		_, err := managementComponent.GetUserAccountStatusByEmail(ctx, realmName, email)

		assert.NotNil(t, err)
	})

	var users = []kc.UserRepresentation{searchedUser}
	var count = len(users)
	mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmReq, realmName, "email", "="+email).Return(kc.UsersPageRepresentation{
		Count: &count,
		Users: users,
	}, nil).AnyTimes()

	t.Run("GetCredentials fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(gomock.Any(), realmName, userID).Return(nil, anyError)

		_, err := managementComponent.GetUserAccountStatusByEmail(ctx, realmName, email)

		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		var anyCredential = kc.CredentialRepresentation{}
		mocks.keycloakClient.EXPECT().GetCredentials(gomock.Any(), realmName, userID).Return([]kc.CredentialRepresentation{anyCredential, anyCredential}, nil)
		mocks.onboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(true, nil)

		res, err := managementComponent.GetUserAccountStatusByEmail(ctx, realmName, email)

		assert.Nil(t, err)
		assert.Equal(t, email, *res.Email)
		assert.True(t, *res.Enabled)
		assert.True(t, *res.PhoneNumberVerified)
		assert.True(t, *res.OnboardingCompleted)
		assert.Equal(t, 2, *res.NumberOfCredentials)
	})
}

func TestGetClientRolesForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var clientID = "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get role with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "client name"

		var kcRoleRep = kc.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mocks.keycloakClient.EXPECT().GetClientRoleMappings(accessToken, realmName, userID, clientID).Return(kcRolesRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetClientRolesForUser(ctx, "master", userID, clientID)

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.ID)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerID)
		assert.Equal(t, description, *apiRoleRep.Description)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetClientRoleMappings(accessToken, realmName, userID, clientID).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClientRolesForUser(ctx, "master", userID, clientID)

		assert.NotNil(t, err)
	})
}

func TestAddClientRolesToUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var clientID = "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Add role with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "client name"

		mocks.keycloakClient.EXPECT().AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, userID, clientID string, roles []kc.RoleRepresentation) error {
				var role = roles[0]
				assert.Equal(t, id, *role.ID)
				assert.Equal(t, name, *role.Name)
				assert.Equal(t, clientRole, *role.ClientRole)
				assert.Equal(t, composite, *role.Composite)
				assert.Equal(t, containerID, *role.ContainerID)
				assert.Equal(t, description, *role.Description)
				return nil
			})

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		var roleRep = api.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
		}
		var rolesRep []api.RoleRepresentation
		rolesRep = append(rolesRep, roleRep)

		err := managementComponent.AddClientRolesToUser(ctx, "master", userID, clientID, rolesRep)

		assert.Nil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).Return(fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.AddClientRolesToUser(ctx, "master", userID, clientID, []api.RoleRepresentation{})

		assert.NotNil(t, err)
	})
}

func TestDeleteClientRolesFromUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var clientID = "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Delete role with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var name = "client name"

		mocks.keycloakClient.EXPECT().DeleteClientRolesFromUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		err := managementComponent.DeleteClientRolesFromUser(ctx, realmName, userID, clientID, id, name)

		assert.Nil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteClientRolesFromUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).Return(fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.DeleteClientRolesFromUser(ctx, "master", userID, clientID, "", "")

		assert.NotNil(t, err)
	})
}

func TestGetRolesOfUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get role with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = false
		var name = "client name"

		var kcRoleRep = kc.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
		}

		var kcRoleRepWithAttributes = kc.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
			Attributes: &map[string][]string{
				"BUSINESS_ROLE_FLAG": {"true"},
			},
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return(kcRolesRep, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, *kcRoleRep.ID).Return(kcRoleRepWithAttributes, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.ID)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerID)
		assert.Equal(t, description, *apiRoleRep.Description)
	})
	t.Run("GetNonBusinessRole", func(t *testing.T) {
		var id = "1234-7454-4516"
		var kcRoleRep = kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return([]kc.RoleRepresentation{kcRoleRep}, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, *kcRoleRep.ID).Return(kcRoleRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		res, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, []api.RoleRepresentation{}, res)
	})

	t.Run("Error GetRole", func(t *testing.T) {
		var id = "1234-7454-4516"
		var kcRoleRep = kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return([]kc.RoleRepresentation{kcRoleRep}, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, *kcRoleRep.ID).Return(kcRoleRep, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestAddRoleOfUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var roleID1 = "rol-rol-rol-111"
	var roleID2 = "rol-rol-rol-222"
	var anyError = errors.New("any error")
	var knownRoles = []kc.RoleRepresentation{{ID: &roleID1, Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}}}, {ID: &roleID2}}
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Can't get realm roles", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return(nil, anyError)

		err := managementComponent.AddRoleToUser(ctx, realmName, userID, roleID1)

		assert.Equal(t, anyError, err)
	})

	t.Run("Role does not exists", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return(knownRoles, nil)

		err := managementComponent.AddRoleToUser(ctx, realmName, userID, "not-a-role")

		assert.NotNil(t, err)
	})

	t.Run("Keycloak fails to update roles", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return(knownRoles, nil)
		mocks.keycloakClient.EXPECT().AddRealmLevelRoleMappings(accessToken, realmName, userID, gomock.Any()).Return(anyError)

		err := managementComponent.AddRoleToUser(ctx, realmName, userID, roleID1)

		assert.Equal(t, anyError, err)
	})

	t.Run("Add non business role", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return(knownRoles, nil)

		err := managementComponent.AddRoleToUser(ctx, realmName, userID, roleID2)

		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return(knownRoles, nil)
		mocks.keycloakClient.EXPECT().AddRealmLevelRoleMappings(accessToken, realmName, userID, gomock.Any()).Return(nil)

		err := managementComponent.AddRoleToUser(ctx, realmName, userID, roleID1)

		assert.Nil(t, err)
	})
}

func TestDeleteRoleForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var roleID1 = "rol-rol-rol-111"
	var roleID2 = "rol-rol-rol-222"
	var notOwnedRoleID = "not-a-owned-role"
	var anyError = errors.New("any error")
	var role1 = kc.RoleRepresentation{ID: &roleID1, Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}}}
	var role2 = kc.RoleRepresentation{ID: &roleID2}
	var knownRoles = []kc.RoleRepresentation{role1, role2}
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Can't get user roles", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return(nil, anyError)

		err := managementComponent.DeleteRoleForUser(ctx, realmName, userID, roleID1)

		assert.Equal(t, anyError, err)
	})

	t.Run("Role is not owned by user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return(knownRoles, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID1).Return(role1, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID2).Return(role2, nil).Times(1)
		err := managementComponent.DeleteRoleForUser(ctx, realmName, userID, notOwnedRoleID)

		assert.NotNil(t, err)
	})

	t.Run("Keycloak fails to update roles", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return(knownRoles, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID1).Return(role1, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID2).Return(role2, nil).Times(1)
		mocks.keycloakClient.EXPECT().DeleteRealmLevelRoleMappings(accessToken, realmName, userID, gomock.Any()).Return(anyError)

		err := managementComponent.DeleteRoleForUser(ctx, realmName, userID, roleID1)

		assert.Equal(t, anyError, err)
	})

	t.Run("Delete Not Business role", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return(knownRoles, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID1).Return(role1, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID2).Return(role2, nil).Times(1)

		err := managementComponent.DeleteRoleForUser(ctx, realmName, userID, roleID2)

		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return(knownRoles, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID1).Return(role1, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID2).Return(role2, nil).Times(1)
		mocks.keycloakClient.EXPECT().DeleteRealmLevelRoleMappings(accessToken, realmName, userID, gomock.Any()).Return(nil)

		err := managementComponent.DeleteRoleForUser(ctx, realmName, userID, roleID1)

		assert.Nil(t, err)
	})
}

func TestGetGroupsOfUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get groups with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var name = "client name"

		var kcGroupRep = kc.GroupRepresentation{
			ID:   &id,
			Name: &name,
		}

		var kcGroupsRep []kc.GroupRepresentation
		kcGroupsRep = append(kcGroupsRep, kcGroupRep)

		mocks.keycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return(kcGroupsRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiGroupsRep, err := managementComponent.GetGroupsOfUser(ctx, "master", userID)

		var apiGroupRep = apiGroupsRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiGroupRep.ID)
		assert.Equal(t, name, *apiGroupRep.Name)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return([]kc.GroupRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetGroupsOfUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestSetGroupsToUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "a-valid-access-token"
	var realmName = "my-realm"
	var userID = "USER-IDEN-IFIE-R123"
	var groupID = "user-group-1"
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	t.Run("AddGroupToUser: KC fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().AddGroupToUser(accessToken, realmName, userID, groupID).Return(errors.New("kc error"))
		var err = managementComponent.AddGroupToUser(ctx, realmName, userID, groupID)
		assert.NotNil(t, err)
	})
	t.Run("DeleteGroupForUser: KC fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroupFromUser(accessToken, realmName, userID, groupID).Return(errors.New("kc error"))
		var err = managementComponent.DeleteGroupForUser(ctx, realmName, userID, groupID)
		assert.NotNil(t, err)
	})
	t.Run("AddGroupToUser: Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().AddGroupToUser(accessToken, realmName, userID, groupID).Return(nil)
		var err = managementComponent.AddGroupToUser(ctx, realmName, userID, groupID)
		assert.Nil(t, err)
	})
	t.Run("DeleteGroupForUser: Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroupFromUser(accessToken, realmName, userID, groupID).Return(nil)
		var err = managementComponent.DeleteGroupForUser(ctx, realmName, userID, groupID)
		assert.Nil(t, err)
	})
}

func TestGetAvailableTrustIDGroups(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var realmName = "master"

	var res, err = component.GetAvailableTrustIDGroups(context.TODO(), realmName)
	assert.Nil(t, err)
	assert.Len(t, res, len(allowedTrustIDGroups))
}

func TestGetTrustIDGroupsOfUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var groups = []string{"some", "/groups"}
	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var attrbs = kc.Attributes{constants.AttrbTrustIDGroups: groups}
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Keycloak fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, errors.New("kc error"))
		var _, err = component.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.NotNil(t, err)
	})
	t.Run("User without attributes", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, nil)
		var res, err = component.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Len(t, res, 0)
	})
	t.Run("User has attributes", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Attributes: &attrbs}, nil)
		var res, err = component.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Equal(t, "some", res[0])
		assert.Equal(t, "groups", res[1]) // Without heading slash
	})
}

func TestSetTrustIDGroupsToUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="

	var username = "user"
	var realmName = "master"
	var userID = "789-1234-5678"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Set groups with success", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			Username: &username,
		}
		grpNames := []string{"grp1", "grp2"}
		extGrpNames := []string{"/grp1", "/grp2"}
		attrs := make(kc.Attributes)
		attrs.Set(constants.AttrbTrustIDGroups, extGrpNames)
		var kcUserRep2 = kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrs,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, kcUserRep2).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.Nil(t, err)
	})

	t.Run("Try to set unknown group", func(t *testing.T) {
		grpNames := []string{"grp1", "grp3"}
		attrs := make(map[string][]string)
		attrs["trustIDGroups"] = grpNames

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.NotNil(t, err)
	})

	t.Run("Error while get user", func(t *testing.T) {
		grpNames := []string{"grp1", "grp2"}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.NotNil(t, err)
	})

	t.Run("Error while update user", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			Username: &username,
		}
		grpNames := []string{"grp1", "grp2"}
		extGrpNames := []string{"/grp1", "/grp2"}
		attrs := make(kc.Attributes)
		attrs.Set(constants.AttrbTrustIDGroups, extGrpNames)
		var kcUserRep2 = kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrs,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, kcUserRep2).Return(fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.NotNil(t, err)
	})
}

func TestResetPassword(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var password = "P@ssw0rd"
	var typePassword = "password"
	var username = "username"

	t.Run("Change password", func(t *testing.T) {
		var kcCredRep = kc.CredentialRepresentation{
			Type:  &typePassword,
			Value: &password,
		}

		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, kcCredRep).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		var passwordRep = api.PasswordRepresentation{
			Value: &password,
		}

		_, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
	})
	t.Run("No password offered", func(t *testing.T) {
		var id = "master_id"
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var policy = "forceExpiredPasswordChange(365) and specialChars(1) and upperCase(1) and lowerCase(1) and length(4) and digits(1) and notUsername(undefined)"
		var kcRealmRep = kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
			PasswordPolicy:  &policy,
		}

		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kcRealmRep, nil).AnyTimes()

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		var passwordRep = api.PasswordRepresentation{
			Value: nil,
		}

		pwd, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
		assert.NotNil(t, pwd)
	})
	t.Run("No password offered, no keycloak policy", func(t *testing.T) {
		var id = "master_id"

		var kcRealmRep = kc.RealmRepresentation{
			ID: &id,
		}

		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kcRealmRep, nil).AnyTimes()

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		var passwordRep = api.PasswordRepresentation{
			Value: nil,
		}

		pwd, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
		assert.NotNil(t, pwd)
	})
	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, gomock.Any()).Return(fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		var passwordRep = api.PasswordRepresentation{
			Value: &password,
		}
		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Invalid input")
		_, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.NotNil(t, err)
	})
}

func TestRecoveryCode(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var username = "username"
	var code = "123456"

	t.Run("RecoveryCode", func(t *testing.T) {
		var kcCodeRep = kc.RecoveryCodeRepresentation{
			Code: &code,
		}

		mocks.keycloakClient.EXPECT().CreateRecoveryCode(accessToken, realmName, userID).Return(kcCodeRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		recoveryCode, err := managementComponent.CreateRecoveryCode(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, code, recoveryCode)
	})

	t.Run("RecoveryCode already exists", func(t *testing.T) {
		var err409 = kc.HTTPError{
			HTTPStatus: 409,
			Message:    "Conflict",
		}
		var kcCodeRep = kc.RecoveryCodeRepresentation{}

		mocks.keycloakClient.EXPECT().CreateRecoveryCode(accessToken, realmName, userID).Return(kcCodeRep, err409)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "409:Conflict")
		_, err := managementComponent.CreateRecoveryCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		var kcCodeRep = kc.RecoveryCodeRepresentation{}
		mocks.keycloakClient.EXPECT().CreateRecoveryCode(accessToken, realmName, userID).Return(kcCodeRep, fmt.Errorf("Error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Error")
		_, err := managementComponent.CreateRecoveryCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestActivationCode(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var username = "username"
	var code = "123456"

	t.Run("ActivationCode", func(t *testing.T) {
		var kcCodeRep = kc.ActivationCodeRepresentation{
			Code: &code,
		}

		mocks.keycloakClient.EXPECT().CreateActivationCode(accessToken, realmName, userID).Return(kcCodeRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		activationCode, err := managementComponent.CreateActivationCode(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, code, activationCode)
	})

	t.Run("Error", func(t *testing.T) {
		var kcCodeRep = kc.ActivationCodeRepresentation{}
		mocks.keycloakClient.EXPECT().CreateActivationCode(accessToken, realmName, userID).Return(kcCodeRep, fmt.Errorf("Error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Error")
		_, err := managementComponent.CreateActivationCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestExecuteActionsEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "1245-7854-8963"
	var reqActions = []api.RequiredAction{initPasswordAction, "action1", "action2"}
	var actions = []string{initPasswordAction, "action1", "action2"}
	var key1 = "key1"
	var value1 = "value1"
	var key2 = "key2"
	var value2 = "value2"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Send email actions", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions, key1, value1, key2, value2).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions, key1, value1, key2, value2)

		assert.Nil(t, err)
	})
	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions).Return(fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions)

		assert.NotNil(t, err)
	})
	t.Run("Send email actions, but not sms-password-set", func(t *testing.T) {
		var actions2 = []string{"action1", "action2"}
		var reqActions2 = []api.RequiredAction{"action1", "action2"}
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions2, key1, value1, key2, value2).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions2, key1, value1, key2, value2)

		assert.Nil(t, err)
	})
}

func TestRevokeAccreditations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var accessToken = "my-access-token"
	var realmName = "my-realm"
	var userID = "my-user-id"
	var username = "pseudo613"
	var kcUser = kc.UserRepresentation{
		ID:       &userID,
		Username: &username,
	}
	var anyError = errors.New("any error")
	var ctx = context.TODO()
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Can't get keycloak user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, anyError)
		var err = component.RevokeAccreditations(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("User has no accreditation", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		var err = component.RevokeAccreditations(ctx, realmName, userID)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, http.StatusNotFound, err.(errorhandler.Error).Status)
	})
	t.Run("User has no active accreditation", func(t *testing.T) {
		var attrbs = kc.Attributes{
			constants.AttrbAccreditations: []string{`{"type":"DEP","expiryDate":"31.12.2059","creationMillis":1643700000000,"revoked":true}`},
		}
		kcUser.Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		var err = component.RevokeAccreditations(ctx, realmName, userID)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, http.StatusNotFound, err.(errorhandler.Error).Status)
	})
	t.Run("Fails to update keycloak user", func(t *testing.T) {
		var attrbs = kc.Attributes{
			constants.AttrbAccreditations: []string{`{"type":"DEP","expiryDate":"31.12.2059","creationMillis":1643700000000}`},
		}
		kcUser.Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(anyError)
		var err = component.RevokeAccreditations(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Success", func(t *testing.T) {
		var attrbs = kc.Attributes{
			constants.AttrbAccreditations: []string{`{"type":"DEP","expiryDate":"31.12.2059","creationMillis":1643700000000}`},
		}
		kcUser.Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		var err = component.RevokeAccreditations(ctx, realmName, userID)
		assert.Nil(t, err)
	})
}

func TestSendSmsCode(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var username = "userName"
	var userID = "1245-7854-8963"

	t.Run("Send new sms code", func(t *testing.T) {
		var code = "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, realmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		codeRes, err := managementComponent.SendSmsCode(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, "1234", codeRes)
	})
	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, realmName, userID).Return(kc.SmsCodeRepresentation{}, fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Invalid input")
		_, err := managementComponent.SendSmsCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestSendOnboardingEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var onboardingRedirectURI = "http://successURL"
	var onboardingClientID = "onboardingid"
	var accessToken = "TOKEN=="
	var realmName = "master"
	var customerRealmName = "customer"
	var userID = "1245-7854-8963"
	var username = "username"
	var ctx = context.Background()
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, customerRealmName)
	var anyError = errors.New("unexpected error")

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()
	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("InSocialRealm-Can't get oidc token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", anyError)

		err := managementComponent.SendOnboardingEmailInSocialRealm(ctx, userID, realmName, false)
		assert.NotNil(t, err)
	})

	t.Run("InSocialRealm-Fails to retrieve realm configuration", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, customerRealmName).Return(configuration.RealmConfiguration{}, anyError)

		err := managementComponent.SendOnboardingEmailInSocialRealm(ctx, userID, customerRealmName, false)
		assert.NotNil(t, err)
	})

	t.Run("Configuration is missing", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, customerRealmName).Return(configuration.RealmConfiguration{
			OnboardingRedirectURI: &onboardingRedirectURI,
		}, nil)

		err := managementComponent.SendOnboardingEmail(ctx, realmName, userID, customerRealmName, false)
		assert.NotNil(t, err)
	})

	mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, customerRealmName).Return(configuration.RealmConfiguration{
		OnboardingRedirectURI: &onboardingRedirectURI,
		OnboardingClientID:    &onboardingClientID,
	}, nil).AnyTimes()

	t.Run("Fails to retrieve user in KC", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, anyError)

		err := managementComponent.SendOnboardingEmail(ctx, realmName, userID, customerRealmName, false)
		assert.NotNil(t, err)
	})

	t.Run("User with invalid onboardingCOmpleted attribute", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetString(constants.AttrbOnboardingCompleted, "wrong")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
			ID:         &userID,
			Username:   &username,
			Attributes: &attributes,
		}, nil)
		mocks.onboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, anyError)

		err := managementComponent.SendOnboardingEmail(ctx, realmName, userID, customerRealmName, false)
		assert.NotNil(t, err)
	})

	t.Run("User already onboarded", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetBool(constants.AttrbOnboardingCompleted, true)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
			ID:         &userID,
			Username:   &username,
			Attributes: &attributes,
		}, nil)
		mocks.onboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(true, nil)

		err := managementComponent.SendOnboardingEmail(ctx, realmName, userID, customerRealmName, false)
		assert.NotNil(t, err)
	})

	t.Run("Failure to send mail", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
			ID:       &userID,
			Username: &username,
		}, nil)

		mocks.onboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil)
		var computedOnboardingRedirectURI = onboardingRedirectURI + "?customerRealm=" + customerRealmName
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, realmName, customerRealmName, gomock.Any()).Return(computedOnboardingRedirectURI, nil)

		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, realmName, userID, username,
			onboardingClientID, computedOnboardingRedirectURI, customerRealmName, true).Return(anyError)

		err := managementComponent.SendOnboardingEmail(ctx, realmName, userID, customerRealmName, true)
		assert.NotNil(t, err)
	})

	mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, realmName).Return(configuration.RealmConfiguration{
		OnboardingRedirectURI: &onboardingRedirectURI,
		OnboardingClientID:    &onboardingClientID,
	}, nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
			ID:       &userID,
			Username: &username,
		}, nil)
		mocks.onboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil)
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, realmName, realmName, gomock.Any()).Return(onboardingRedirectURI, nil)
		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, gomock.Any(), false).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.SendOnboardingEmail(ctx, realmName, userID, realmName, false)
		assert.Nil(t, err)
	})
}

func TestSendReminderEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "1245-7854-8963"

	var key1 = "key1"
	var value1 = "value1"
	var key2 = "key2"
	var value2 = "value2"
	var key3 = "key3"
	var value3 = "value3"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Send email", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendReminderEmail(accessToken, realmName, userID, key1, value1, key2, value2, key3, value3).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SendReminderEmail(ctx, "master", userID, key1, value1, key2, value2, key3, value3)

		assert.Nil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendReminderEmail(accessToken, realmName, userID).Return(fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SendReminderEmail(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestResetSmsCounter(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "1245-7854-8963"
	var id = "1234-7454-4516"
	var username = "username"
	var email = "toto@elca.ch"
	var enabled = true
	var emailVerified = true
	var firstName = "Titi"
	var lastName = "Tutu"
	var phoneNumber = "+41789456"
	var phoneNumberVerified = true
	var label = "Label"
	var gender = "M"
	var birthDate = "01/01/1988"
	var createdTimestamp = time.Now().UTC().Unix()
	var attributes = make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
	attributes.SetString(constants.AttrbLabel, label)
	attributes.SetString(constants.AttrbGender, gender)
	attributes.SetString(constants.AttrbBirthDate, birthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
	attributes.SetInt(constants.AttrbSmsSent, 5)
	attributes.SetInt(constants.AttrbSmsAttempts, 5)

	var kcUserRep = kc.UserRepresentation{
		ID:               &id,
		Username:         &username,
		Email:            &email,
		Enabled:          &enabled,
		EmailVerified:    &emailVerified,
		FirstName:        &firstName,
		LastName:         &lastName,
		Attributes:       &attributes,
		CreatedTimestamp: &createdTimestamp,
	}

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Reset SMS counter", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, kcUserRep).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.ResetSmsCounter(ctx, "master", userID)

		assert.Nil(t, err)
	})

	t.Run("Error at GetUser", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, fmt.Errorf("error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		err := managementComponent.ResetSmsCounter(ctx, "master", userID)

		assert.NotNil(t, err)
	})

	t.Run("Error at UpdateUser", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, kcUserRep).Return(fmt.Errorf("error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		err := managementComponent.ResetSmsCounter(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestGetCredentialsForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmReq = "master"
	var realmName = "otherRealm"
	var userID = "1245-7854-8963"

	t.Run("Get credentials for user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{}, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)

		_, err := managementComponent.GetCredentialsForUser(ctx, realmName, userID)

		assert.Nil(t, err)
	})
}

func TestDeleteCredentialsForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmReq = "master"
	var realmName = "master"
	var userID = "1245-7854-8963"
	var credMfa1 = kc.CredentialRepresentation{ID: ptr("cred-mfa-1"), Type: ptr("any-mfa")}
	var credMfa2 = kc.CredentialRepresentation{ID: ptr("cred-mfa-2"), Type: ptr("any-mfa")}
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()
	mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{credMfa1, credMfa2}, nil)
		mocks.keycloakClient.EXPECT().DeleteCredential(accessToken, realmName, userID, *credMfa1.ID).Return(nil)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.DeleteCredentialsForUser(ctx, realmName, userID, *credMfa1.ID)

		assert.Nil(t, err)
	})

	t.Run("GetCredentials fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{}, errors.New("error"))

		err := managementComponent.DeleteCredentialsForUser(ctx, realmName, userID, *credMfa1.ID)
		assert.NotNil(t, err)
	})

	t.Run("Error at deleting the credential", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{credMfa1, credMfa2}, nil)
		mocks.keycloakClient.EXPECT().DeleteCredential(accessToken, realmName, userID, *credMfa1.ID).Return(errors.New("error"))

		err := managementComponent.DeleteCredentialsForUser(ctx, realmName, userID, *credMfa1.ID)
		assert.NotNil(t, err)
	})
}

func TestUnlockCredentialForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "1245-7854-8963"
	var credentialID = "987-654-321"
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Detect credential type-Keycloak call fails", func(t *testing.T) {
		var kcErr = errors.New("keycloak error")
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return(nil, kcErr)

		var err = managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.Equal(t, kcErr, err)
	})

	t.Run("Detect credential type-Credential not found", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return(nil, nil)

		var err = managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.NotNil(t, err)
	})

	var foundCredType = "ctpapercard"
	var credentials = []kc.CredentialRepresentation{{ID: &credentialID, Type: &foundCredType}}
	mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return(credentials, nil).AnyTimes()

	t.Run("Detect credential type-Credential found", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ResetPapercardFailures(accessToken, realmName, userID, credentialID).Return(nil)

		var err = managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.Nil(t, err)
	})

	t.Run("Can't unlock paper card", func(t *testing.T) {
		var unlockErr = errors.New("unlock error")
		mocks.keycloakClient.EXPECT().ResetPapercardFailures(accessToken, realmName, userID, credentialID).Return(unlockErr)

		var err = managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.Equal(t, unlockErr, err)
	})
}

func TestClearUserLoginFailures(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realm = "master"
	var userID = "1245-7854-8963"
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Error occured", func(t *testing.T) {
		var expectedError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().ClearUserLoginFailures(accessToken, realm, userID).Return(expectedError)
		var err = component.ClearUserLoginFailures(ctx, realm, userID)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ClearUserLoginFailures(accessToken, realm, userID).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		var err = component.ClearUserLoginFailures(ctx, realm, userID)
		assert.Nil(t, err)
	})
}

func TestGetAttackDetectionStatus(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realm = "master"
	var userID = "1245-7854-8963"
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)
	var kcResult = map[string]interface{}{}

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Error occured", func(t *testing.T) {
		var expectedError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetAttackDetectionStatus(accessToken, realm, userID).Return(kcResult, expectedError)
		var _, err = component.GetAttackDetectionStatus(ctx, realm, userID)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		var expectedFailures int64 = 57
		kcResult["numFailures"] = expectedFailures
		mocks.keycloakClient.EXPECT().GetAttackDetectionStatus(accessToken, realm, userID).Return(kcResult, nil)
		var res, err = component.GetAttackDetectionStatus(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Equal(t, expectedFailures, *res.NumFailures)
	})
}

func TestGetRoles(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get roles with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = false
		var name = "name"

		var kcRoleRep = kc.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
			Attributes: &map[string][]string{
				"BUSINESS_ROLE_FLAG": {"true"},
			},
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return(kcRolesRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetRoles(ctx, "master")

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.ID)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerID)
		assert.Equal(t, description, *apiRoleRep.Description)
	})

	t.Run("NonBusinessRole are not returned", func(t *testing.T) {
		var id = "1234-7454-4516"
		var kcRoleRep = kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return([]kc.RoleRepresentation{kcRoleRep}, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetRoles(ctx, "master")

		assert.Nil(t, err)
		assert.Equal(t, []api.RoleRepresentation{}, apiRolesRep)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRoles(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestGetRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get roles with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = false
		var name = "name"
		var attributes = map[string][]string{
			"BUSINESS_ROLE_FLAG": {"true"},
		}

		var kcRoleRep = kc.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
			Attributes:  &attributes,
		}

		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, id).Return(kcRoleRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRoleRep, err := managementComponent.GetRole(ctx, "master", id)

		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.ID)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerID)
		assert.Equal(t, description, *apiRoleRep.Description)
		assert.Equal(t, attributes, *apiRoleRep.Attributes)
	})

	t.Run("NonBusinessRole is not returned", func(t *testing.T) {
		var id = "1234-7454-4516"
		var kcRoleRep = kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, id).Return(kcRoleRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRole(ctx, "master", id)

		assert.NotNil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		var id = "1234-7454-4516"
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, id).Return(kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRole(ctx, "master", id)

		assert.NotNil(t, err)
	})
}

func TestCreateRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var username = "username"
	var userID = "testUserID"
	var name = "test"
	var realmName = "master"
	var roleID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var locationURL = "http://toto.com/realms/" + roleID

	t.Run("Create", func(t *testing.T) {
		var kcRoleRep = kc.RoleRepresentation{
			Name:       &name,
			Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}},
		}

		mocks.keycloakClient.EXPECT().CreateRole(accessToken, realmName, kcRoleRep).Return(locationURL, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		var roleRep = api.RoleRepresentation{
			Name: &name,
		}

		location, err := managementComponent.CreateRole(ctx, realmName, roleRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		var kcRoleRep = kc.RoleRepresentation{
			Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}},
		}

		mocks.keycloakClient.EXPECT().CreateRole(accessToken, realmName, kcRoleRep).Return("", fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		var roleRep = api.RoleRepresentation{}
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		location, err := managementComponent.CreateRole(ctx, realmName, roleRep)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	})
}

func TestUpdateRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var accessToken = "TOKEN=="
	var roleID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var roleName = "roleName"
	var realmName = "master"
	var username = "username"
	var attributes = map[string][]string{
		"BUSINESS_ROLE_FLAG": {"true"},
	}

	var role = kc.RoleRepresentation{
		ID:         &roleID,
		Name:       &roleName,
		Attributes: &attributes,
	}
	var inputRole = api.RoleRepresentation{Name: &roleName}
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get role from keycloak fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, anyError)

		err := component.UpdateRole(ctx, realmName, roleID, inputRole)

		assert.Equal(t, anyError, err)
	})
	t.Run("Update role fails in Keycloak", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().UpdateRole(accessToken, realmName, roleID, gomock.Any()).Return(anyError)

		err := component.UpdateRole(ctx, realmName, roleID, inputRole)

		assert.Equal(t, anyError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().UpdateRole(accessToken, realmName, roleID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := component.UpdateRole(ctx, realmName, roleID, inputRole)

		assert.Nil(t, err)
	})
}

func TestDeleteRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var roleID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var roleName = "roleName"
	var realmName = "master"
	var username = "username"
	var userID = "testUserID"

	attributes := map[string][]string{
		"BUSINESS_ROLE_FLAG": {"true"},
	}

	var role = kc.RoleRepresentation{
		ID:         &roleID,
		Name:       &roleName,
		Attributes: &attributes,
	}

	t.Run("Delete role with success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().DeleteRole(accessToken, realmName, roleID).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.DeleteRole(ctx, realmName, roleID)

		assert.Nil(t, err)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(kc.RoleRepresentation{}, errors.New("Error"))

		err := managementComponent.DeleteRole(ctx, realmName, roleID)
		assert.NotNil(t, err)

		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().DeleteRole(accessToken, realmName, roleID).Return(fmt.Errorf("Invalid input"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		err = managementComponent.DeleteRole(ctx, realmName, roleID)
		assert.NotNil(t, err)
	})
}

func TestGetGroups(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get groups with succces, non empty result", func(t *testing.T) {
		var id = "1234-7454-4516"
		var path = "path_group"
		var name = "group1"
		var realmRoles = []string{"role1"}

		var kcGroupRep = kc.GroupRepresentation{
			ID:         &id,
			Name:       &name,
			Path:       &path,
			RealmRoles: &realmRoles,
		}

		var kcGroupsRep []kc.GroupRepresentation
		kcGroupsRep = append(kcGroupsRep, kcGroupRep)

		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realmName).Return(kcGroupsRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiGroupsRep, err := managementComponent.GetGroups(ctx, "master")

		var apiGroupRep = apiGroupsRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiGroupRep.ID)
		assert.Equal(t, name, *apiGroupRep.Name)
	})

	t.Run("Get groups with success, empty result", func(t *testing.T) {
		var kcGroupsRep []kc.GroupRepresentation
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realmName).Return(kcGroupsRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		apiGroupsRep, err := managementComponent.GetGroups(ctx, "master")

		assert.Nil(t, err)
		assert.NotNil(t, apiGroupsRep)
		assert.Equal(t, 0, len(apiGroupsRep))
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetGroups(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestCreateGroup(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var username = "username"
	var userID = "testUserID"
	var name = "test"
	var realmName = "master"
	var targetRealmName = "DEP"
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var locationURL = "http://toto.com/realms/" + groupID

	t.Run("Create", func(t *testing.T) {
		var kcGroupRep = kc.GroupRepresentation{
			Name: &name,
		}

		mocks.keycloakClient.EXPECT().CreateGroup(accessToken, targetRealmName, kcGroupRep).Return(locationURL, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		var groupRep = api.GroupRepresentation{
			Name: &name,
		}

		location, err := managementComponent.CreateGroup(ctx, targetRealmName, groupRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		var kcGroupRep = kc.GroupRepresentation{}

		mocks.keycloakClient.EXPECT().CreateGroup(accessToken, targetRealmName, kcGroupRep).Return("", fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		var groupRep = api.GroupRepresentation{}
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		location, err := managementComponent.CreateGroup(ctx, targetRealmName, groupRep)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	})
}

func TestDeleteGroup(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var groupName = "groupName"
	var targetRealmName = "DEP"
	var realmName = "master"
	var username = "username"
	var userID = "testUserID"

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}

	t.Run("Delete group with success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroup(accessToken, targetRealmName, groupID).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.configurationDBModule.EXPECT().DeleteAllAuthorizationsWithGroup(ctx, targetRealmName, groupName).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.DeleteGroup(ctx, targetRealmName, groupID)

		assert.Nil(t, err)
	})

	t.Run("Error with DB", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroup(accessToken, targetRealmName, groupID).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.configurationDBModule.EXPECT().DeleteAllAuthorizationsWithGroup(ctx, targetRealmName, groupName).Return(fmt.Errorf("Error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")

		err := managementComponent.DeleteGroup(ctx, targetRealmName, groupID)

		assert.NotNil(t, err)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(kc.GroupRepresentation{}, errors.New("Error"))

		err := managementComponent.DeleteGroup(ctx, targetRealmName, groupID)
		assert.NotNil(t, err)

		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().DeleteGroup(accessToken, targetRealmName, groupID).Return(fmt.Errorf("Invalid input"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		err = managementComponent.DeleteGroup(ctx, targetRealmName, groupID)
		assert.NotNil(t, err)
	})
}

func TestGetAuthorizations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var targetRealmname = "DEP"
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var groupName = "groupName"
	var username = "username"
	var action = "action"

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}

	t.Run("Get authorizations with succces", func(t *testing.T) {
		var configurationAuthz = []configuration.Authorization{
			{
				RealmID:   &realmName,
				GroupName: &groupName,
				Action:    &action,
			},
		}

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.configurationDBModule.EXPECT().GetAuthorizations(ctx, targetRealmname, groupName).Return(configurationAuthz, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmname, groupID).Return(group, nil)

		apiAuthorizationRep, err := managementComponent.GetAuthorizations(ctx, targetRealmname, groupID)

		var matrix = map[string]map[string]map[string]struct{}{
			"action": {},
		}

		var expectedAPIAuthorization = api.AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIAuthorization, apiAuthorizationRep)
	})

	t.Run("Error when retrieving authorizations from DB", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmname, groupID).Return(group, nil)
		mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmname, groupName).Return([]configuration.Authorization{}, fmt.Errorf("Error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")

		_, err := managementComponent.GetAuthorizations(ctx, targetRealmname, groupID)

		assert.NotNil(t, err)
	})

	t.Run("Error with KC", func(t *testing.T) {
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmname, groupID).Return(kc.GroupRepresentation{}, errors.New("Error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")
		_, err := managementComponent.GetAuthorizations(ctx, targetRealmname, groupID)
		assert.NotNil(t, err)
	})
}

func TestUpdateAuthorizations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "customer1"
	var targetRealmName = "DEP"
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var groupName = "groupName"
	var username = "username"

	var realm = kc.RealmRepresentation{
		ID:    &targetRealmName,
		Realm: &targetRealmName,
	}
	var realms = []kc.RealmRepresentation{realm}

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	var groups = []kc.GroupRepresentation{group}

	var action = "MGMT_action"
	var matrix = map[string]map[string]map[string]struct{}{
		action: {},
	}

	var apiAuthorizations = api.AuthorizationsRepresentation{
		Matrix: &matrix,
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()
	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Call to Keycloak.GetGroup fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(kc.GroupRepresentation{}, errors.New("Error"))
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Call to Keycloak GetRealm fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return([]kc.RealmRepresentation{}, errors.New("Unexpected error"))
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Call to Keycloak GetGroups fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return([]kc.GroupRepresentation{}, errors.New("Unexpected error"))
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Call to DB.GetAuthorizations fails", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil),
			mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil),
			mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil),
			mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmName, groupName).Return(nil, errors.New("DB GetAuthorizations fails")),
		)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to create transaction", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil),
			mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil),
			mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil),
			mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmName, groupName).Return([]configuration.Authorization{}, nil),
			mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(nil, errors.New("Unexpected error")),
		)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to add new authorization", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil),
			mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil),
			mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil),
			mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmName, groupName).Return([]configuration.Authorization{}, nil),
			mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil),
			mocks.transaction.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, errors.New("adding authorization failed")),
			mocks.transaction.EXPECT().Close(),
		)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to remove authorization", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil),
			mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil),
			mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil),
			mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmName, groupName).Return([]configuration.Authorization{
				{RealmID: ptr("realm"), GroupName: ptr("group"), Action: ptr("action"), TargetRealmID: ptr("target-realm"), TargetGroupName: ptr("target-group")},
			}, nil),
			mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil),
			// Add authorizations
			mocks.transaction.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil),
			// Remove authorizations
			mocks.transaction.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, errors.New("removing authorization failed")),
			mocks.transaction.EXPECT().Close(),
		)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to commit transaction", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil),
			mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil),
			mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil),
			mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmName, groupName).Return([]configuration.Authorization{}, nil),
			mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil),
			mocks.transaction.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil), // Add authorizations
			mocks.transaction.EXPECT().Commit().Return(errors.New("Unexpected error")),
			mocks.transaction.EXPECT().Close(),
		)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil),
			mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil),
			mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil),
			mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmName, groupName).Return([]configuration.Authorization{}, nil),
			mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil),
			mocks.transaction.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil), // Add authorizations
			mocks.transaction.EXPECT().Commit().Return(nil),
			mocks.producer.EXPECT().SendMessageBytes(gomock.Any()),
			mocks.eventsReporter.EXPECT().ReportEvent(ctx, gomock.Any()),
			mocks.transaction.EXPECT().Close(),
		)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.Nil(t, err)
	})

	t.Run("Authorizations provided not valid", func(t *testing.T) {
		var jsonMatrix = `{
			"Action1": {},
			"Action2": {"*": {}, "realm1": {}}
		}`

		var matrix map[string]map[string]map[string]struct{}
		if err := json.Unmarshal([]byte(jsonMatrix), &matrix); err != nil {
			assert.Fail(t, "")
		}

		var apiAuthorizations = api.AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})
}

func TestAddAuthorization(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var targetRealmName = "DEP"
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var groupName = "groupName"
	var targetGroupName = "targetGroup"
	var targetGroupID = "124352"
	var action = "MGMT_DeleteUser"
	var actionRealm = "MGMT_GetRealm"
	var username = "username"
	var userID = "TestUserID"
	var star = "*"

	var expectedErr = errors.New("test error")

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	var groups = []kc.GroupRepresentation{
		{
			ID:   &targetGroupID,
			Name: &targetGroupName,
		},
	}

	var realm = kc.RealmRepresentation{
		ID:    &targetRealmName,
		Realm: &targetRealmName,
	}
	var realms = []kc.RealmRepresentation{realm}

	var matrix = map[string]map[string]map[string]struct{}{
		action: {targetRealmName: {targetGroupName: {}}},
	}
	apiAuthz := api.AuthorizationsRepresentation{Matrix: &matrix}
	dbAuth := configuration.Authorization{
		RealmID:         &realmName,
		GroupName:       &groupName,
		Action:          &action,
		TargetRealmID:   &targetRealmName,
		TargetGroupName: &targetGroupName,
	}
	var matrixRealm = map[string]map[string]map[string]struct{}{
		actionRealm: {targetRealmName: {star: {}}},
	}
	apiAuthzRealm := api.AuthorizationsRepresentation{Matrix: &matrixRealm}
	dbAuthRealm := configuration.Authorization{
		RealmID:         &realmName,
		GroupName:       &groupName,
		Action:          &actionRealm,
		TargetRealmID:   &targetRealmName,
		TargetGroupName: &star,
	}
	var parent = configuration.Authorization{
		RealmID:         &realmName,
		GroupName:       group.Name,
		Action:          &action,
		TargetRealmID:   &star,
		TargetGroupName: &star,
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Put authorization with success", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(security.ForbiddenError{}).Times(1)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, dbAuth).Return(nil)
		mocks.transaction.EXPECT().Commit().Return(nil)
		mocks.transaction.EXPECT().Close()

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Nil(t, err)
	})

	t.Run("Put authorization (scope realm) with success", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetRealm(realmName, []string{groupName}, actionRealm, targetRealmName).Return(security.ForbiddenError{}).Times(1)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, dbAuthRealm).Return(nil)
		mocks.configurationDBModule.EXPECT().CleanAuthorizationsActionForRealm(ctx, realmName, groupName, targetRealmName, actionRealm)
		mocks.transaction.EXPECT().Commit().Return(nil)
		mocks.transaction.EXPECT().Close()

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthzRealm)

		assert.Nil(t, err)
	})

	t.Run("Put authorization already defined by a parent", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(nil).Times(1)
		mocks.transaction.EXPECT().Commit().Return(nil)
		mocks.transaction.EXPECT().Close()

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Nil(t, err)
	})

	t.Run("Error ReloadAuthorization", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("Error GetGroup", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, expectedErr)

		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("Error checkAllowedTargetRealmsAndGroupNames", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, expectedErr)

		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("Error Validate scope", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		var global = "MGMT_GetActions"
		authorizations := []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       group.Name,
				Action:          &global,
				TargetRealmID:   &targetRealmName,
				TargetGroupName: &star,
			},
		}
		err := managementComponent.AddAuthorization(ctx, realmName, groupID, api.ConvertToAPIAuthorizations(authorizations))

		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())
	})

	t.Run("Error New Transaction", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("Error - Delete children", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		putAuth := api.ConvertToAPIAuthorizations([]configuration.Authorization{parent})
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, star, star).Return(security.ForbiddenError{}).Times(1)
		mocks.configurationDBModule.EXPECT().CleanAuthorizationsActionForEveryRealms(ctx, realmName, groupName, *parent.Action).Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		mocks.transaction.EXPECT().Close()

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, putAuth)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("ERROR - createAuthorization", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(security.ForbiddenError{}).Times(1)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, dbAuth).Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		mocks.transaction.EXPECT().Close()

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("ERROR - Commit", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(security.ForbiddenError{}).Times(1)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, dbAuth).Return(nil)
		mocks.transaction.EXPECT().Commit().Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		mocks.transaction.EXPECT().Close()

		err := managementComponent.AddAuthorization(ctx, realmName, groupID, apiAuthz)

		assert.Equal(t, expectedErr, err)
	})
}

func TestGetAuthorization(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var targetRealmName = "DEP"
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var groupName = "groupName"
	var targetGroupName = "targetGroup"
	var targetGroupID = "124352"
	var action = "MGMT_DeleteUser"
	var globalAction = "MGMT_GetActions"
	var realmAction = "MGMT_GetRealm"
	var username = "username"
	var star = "*"

	var expectedErr = errors.New("test error")

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}

	var targetGroup = kc.GroupRepresentation{
		ID:   &targetGroupID,
		Name: &targetGroupName,
	}

	var extpectedAuthzNegativeMsg = api.AuthorizationMessage{
		Authorized: false,
	}
	var extpectedAuthzPositiveMsg = api.AuthorizationMessage{
		Authorized: true,
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Get assigned authorization with succces - authorized", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, nil).Times(1)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(nil).Times(1)
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)

		assert.Nil(t, err)
		assert.Equal(t, extpectedAuthzPositiveMsg, authzMsg)
	})

	t.Run("Get assigned global authorization with succces - authorized", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetRealm(realmName, []string{groupName}, globalAction, star).Return(nil).Times(1)

		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, "*", "", globalAction)

		assert.Nil(t, err)
		assert.Equal(t, extpectedAuthzPositiveMsg, authzMsg)
	})

	t.Run("Get assigned realm authorization with succces - authorized", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetRealm(realmName, []string{groupName}, realmAction, targetRealmName).Return(nil).Times(1)

		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, "*", realmAction)

		assert.Nil(t, err)
		assert.Equal(t, extpectedAuthzPositiveMsg, authzMsg)
	})

	t.Run("Get authorization with succces - unauthorized", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, nil).Times(1)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(security.ForbiddenError{}).Times(1)
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)

		assert.Nil(t, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - reload failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - group resolution failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, expectedErr).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - target group resolution failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(group, expectedErr).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - validateScope failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, nil).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, "UnknownAction")
		assert.NotNil(t, err)
		assert.Equal(t, "400 ."+constants.MsgErrInvalidParam+"."+constants.Authorization+".action", err.Error())
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - invalid", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, nil).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, globalAction)

		assert.NotNil(t, err)
		assert.Equal(t, "400 ."+constants.MsgErrInvalidParam+"."+constants.Authorization+".scope", err.Error())
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})
}

func TestDeleteAuthorization(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var targetRealmName = "DEP"
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var groupName = "groupName"
	var targetGroupName = "targetGroup"
	var targetGroupID = "124352"
	var action = "MGMT_DeleteUser"
	var username = "username"
	var userID = "testUserID"
	var star = "*"

	var expectedErr = errors.New("test error")

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	var targetGroup = kc.GroupRepresentation{
		ID:   &targetGroupID,
		Name: &targetGroupName,
	}

	dbAuth := configuration.Authorization{
		RealmID:         &realmName,
		GroupName:       &groupName,
		Action:          &action,
		TargetRealmID:   &targetRealmName,
		TargetGroupName: &targetGroupName,
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Delete authorization, no parent, no child - SUCCESS", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, *dbAuth.RealmID, *dbAuth.GroupName, *dbAuth.TargetRealmID, gomock.Any(), *dbAuth.Action).Return(true, nil)

		mocks.configurationDBModule.EXPECT().DeleteAuthorization(ctx, realmName, groupName, targetRealmName, gomock.Any(), action)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)

		assert.Nil(t, err)
	})

	t.Run("Delete global authorization, no parent, no child - SUCCESS", func(t *testing.T) {
		var globalAction = "MGMT_GetActions"
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, realmName, groupName, star, nil, globalAction).Return(true, nil)

		mocks.configurationDBModule.EXPECT().DeleteAuthorization(ctx, realmName, groupName, star, nil, globalAction)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, star, "", globalAction)

		assert.Nil(t, err)
	})

	t.Run("Delete authorization - get Group error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, expectedErr)

		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, "", "", action)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("Delete authorization - get Group 2 error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)

		assert.Equal(t, expectedErr, err)
	})

	t.Run("Delete authorization - get scope error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)

		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, "", "", "FakeAction")

		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.action", err.Error())
	})

	t.Run("Delete authorization - validate scope", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)

		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, star, "MGMT_GetActions")

		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())
	})

	t.Run("Delete authorization, authorizationExists error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, *dbAuth.RealmID, *dbAuth.GroupName, *dbAuth.TargetRealmID, gomock.Any(), *dbAuth.Action).Return(false, expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)

		assert.NotNil(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Delete authorization, delete error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupID).Return(targetGroup, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, *dbAuth.RealmID, *dbAuth.GroupName, *dbAuth.TargetRealmID, gomock.Any(), *dbAuth.Action).Return(true, nil)
		mocks.configurationDBModule.EXPECT().DeleteAuthorization(ctx, realmName, groupName, targetRealmName, gomock.Any(), action).Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action)

		assert.NotNil(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestGetClientRoles(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var clientID = "15436-464-4"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get roles with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "name"

		var kcRoleRep = kc.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mocks.keycloakClient.EXPECT().GetClientRoles(accessToken, realmName, clientID).Return(kcRolesRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetClientRoles(ctx, "master", clientID)

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.ID)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerID)
		assert.Equal(t, description, *apiRoleRep.Description)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetClientRoles(accessToken, realmName, clientID).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClientRoles(ctx, "master", clientID)

		assert.NotNil(t, err)
	})
}

func TestCreateClientRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var clientID = "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Add role with succces", func(t *testing.T) {
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "client name"

		var locationURL = "http://location.url"

		mocks.keycloakClient.EXPECT().CreateClientRole(accessToken, realmName, clientID, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, clientID string, role kc.RoleRepresentation) (string, error) {
				assert.Equal(t, id, *role.ID)
				assert.Equal(t, name, *role.Name)
				assert.Equal(t, clientRole, *role.ClientRole)
				assert.Equal(t, composite, *role.Composite)
				assert.Equal(t, containerID, *role.ContainerID)
				assert.Equal(t, description, *role.Description)
				return locationURL, nil
			})

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		var roleRep = api.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
		}

		location, err := managementComponent.CreateClientRole(ctx, "master", clientID, roleRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CreateClientRole(accessToken, realmName, clientID, gomock.Any()).Return("", fmt.Errorf("Unexpected error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.CreateClientRole(ctx, "master", clientID, api.RoleRepresentation{})

		assert.NotNil(t, err)
	})
}

func TestDeleteClientRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "test"
	var clientID = "456-789-147"
	var roleID = "123-456-789"

	var role = kc.RoleRepresentation{
		ID:          ptrString("1234-7454-4516"),
		Name:        ptrString("name"),
		ClientRole:  ptrBool(true),
		Composite:   ptrBool(false),
		ContainerID: ptrString("456-789-147"),
		Description: ptrString("description role"),
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("SUCCESS", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().DeleteRole(accessToken, realmName, roleID).Return(nil)

		err := managementComponent.DeleteClientRole(ctx, realmName, clientID, roleID)
		assert.Nil(t, err)
	})

	t.Run("Get role failed", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		err := managementComponent.DeleteClientRole(ctx, realmName, clientID, roleID)
		assert.NotNil(t, err)
	})

	t.Run("Delete role failed", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().DeleteRole(accessToken, realmName, roleID).Return(fmt.Errorf("Unexpected error"))

		err := managementComponent.DeleteClientRole(ctx, realmName, clientID, roleID)
		assert.NotNil(t, err)
	})

	t.Run("Delete not a client role", func(t *testing.T) {
		var role = kc.RoleRepresentation{
			ID:          ptrString("1234-7454-4516"),
			Name:        ptrString("name"),
			ClientRole:  ptrBool(false),
			Composite:   ptrBool(false),
			ContainerID: ptrString(""),
			Description: ptrString("description role"),
		}

		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)

		err := managementComponent.DeleteClientRole(ctx, realmName, clientID, roleID)
		assert.NotNil(t, err)
		assert.Equal(t, errorhandler.CreateNotFoundError("role"), err)
	})

	t.Run("Delete clientID != containerID", func(t *testing.T) {
		var role = kc.RoleRepresentation{
			ID:          ptrString("1234-7454-4516"),
			Name:        ptrString("name"),
			ClientRole:  ptrBool(true),
			Composite:   ptrBool(false),
			ContainerID: ptrString("otherCLIENT"),
			Description: ptrString("description role"),
		}

		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)

		err := managementComponent.DeleteClientRole(ctx, realmName, clientID, roleID)
		assert.NotNil(t, err)
		assert.Equal(t, errorhandler.CreateNotFoundError("role"), err)
	})
}

func TestGetRealmCustomConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmID = "master_id"

	mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()
	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get existing config", func(t *testing.T) {
		var id = realmID
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var kcRealmRep = kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)

		var clientID = "ClientID"
		var redirectURI = "http://redirect.url.com/test"

		var realmConfig = configuration.RealmConfiguration{
			DefaultClientID:    &clientID,
			DefaultRedirectURI: &redirectURI,
		}

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, realmID).Return(realmConfig, nil)

		configJSON, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.Nil(t, err)
		assert.Equal(t, *configJSON.DefaultClientID, *realmConfig.DefaultClientID)
		assert.Equal(t, *configJSON.DefaultRedirectURI, *realmConfig.DefaultRedirectURI)
	})

	t.Run("Get empty config", func(t *testing.T) {
		var id = realmID
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var kcRealmRep = kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, realmID).Return(configuration.RealmConfiguration{}, errorhandler.Error{})

		configJSON, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.Nil(t, err)
		assert.Nil(t, configJSON.DefaultClientID)
		assert.Nil(t, configJSON.DefaultRedirectURI)
	})

	t.Run("Unknown realm", func(t *testing.T) {
		var id = realmID
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var kcRealmRep = kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, errors.New("error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.NotNil(t, err)
	})

	t.Run("DB error", func(t *testing.T) {
		var id = realmID
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var kcRealmRep = kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, realmID).Return(configuration.RealmConfiguration{}, errors.New("error"))

		_, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.NotNil(t, err)
	})
}

func TestUpdateRealmCustomConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmID = "master_id"

	var id = realmID
	var keycloakVersion = "4.8.3"
	var realm = "master"
	var displayName = "Master"
	var enabled = true

	var kcRealmRep = kc.RealmRepresentation{
		ID:              &id,
		KeycloakVersion: &keycloakVersion,
		Realm:           &realm,
		DisplayName:     &displayName,
		Enabled:         &enabled,
	}

	var clients = make([]kc.ClientRepresentation, 2)
	var clientID1 = "clientID1"
	var clientName1 = "clientName1"
	var redirectURIs1 = []string{"https://www.cloudtrust.io/*", "https://www.cloudtrust-old.com/*"}
	var clientID2 = "clientID2"
	var clientName2 = "clientName2"
	var redirectURIs2 = []string{"https://www.cloudtrust2.io/*", "https://www.cloudtrust2-old.com/*"}
	clients[0] = kc.ClientRepresentation{
		ClientID:     &clientID1,
		Name:         &clientName1,
		RedirectUris: &redirectURIs1,
	}
	clients[1] = kc.ClientRepresentation{
		ClientID:     &clientID2,
		Name:         &clientName2,
		RedirectUris: &redirectURIs2,
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	var clientID = "clientID1"
	var redirectURI = "https://www.cloudtrust.io/test"
	var configInit = api.RealmCustomConfiguration{
		DefaultClientID:    &clientID,
		DefaultRedirectURI: &redirectURI,
	}

	mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Update config with appropriate values", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)
		mocks.keycloakClient.EXPECT().GetClients(accessToken, realmID).Return(clients, nil)
		mocks.configurationDBModule.EXPECT().StoreOrUpdateConfiguration(ctx, realmID, gomock.Any()).Return(nil)
		err := managementComponent.UpdateRealmCustomConfiguration(ctx, realmID, configInit)

		assert.Nil(t, err)
	})

	t.Run("Update config with unknown client ID", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)
		mocks.keycloakClient.EXPECT().GetClients(accessToken, realmID).Return(clients, nil)

		var clientID = "clientID1Nok"
		var redirectURI = "https://www.cloudtrust.io/test"
		var configInit = api.RealmCustomConfiguration{
			DefaultClientID:    &clientID,
			DefaultRedirectURI: &redirectURI,
		}
		err := managementComponent.UpdateRealmCustomConfiguration(ctx, realmID, configInit)

		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		e := err.(errorhandler.Error)
		assert.Equal(t, 400, e.Status)
	})

	t.Run("Update config with invalid redirect URI", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)
		mocks.keycloakClient.EXPECT().GetClients(accessToken, realmID).Return(clients, nil)

		var clientID = "clientID1"
		var redirectURI = "https://www.cloudtrustnok.io/test"
		var configInit = api.RealmCustomConfiguration{
			DefaultClientID:    &clientID,
			DefaultRedirectURI: &redirectURI,
		}
		err := managementComponent.UpdateRealmCustomConfiguration(ctx, realmID, configInit)

		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		e := err.(errorhandler.Error)
		assert.Equal(t, 400, e.Status)
	})

	t.Run("Update config with invalid redirect URI (trying to take advantage of the dots in the url)", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)
		mocks.keycloakClient.EXPECT().GetClients(accessToken, realmID).Return(clients, nil)

		var clientID = "clientID1"
		var redirectURI = "https://wwwacloudtrust.io/test"
		var configInit = api.RealmCustomConfiguration{
			DefaultClientID:    &clientID,
			DefaultRedirectURI: &redirectURI,
		}
		err := managementComponent.UpdateRealmCustomConfiguration(ctx, realmID, configInit)

		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		e := err.(errorhandler.Error)
		assert.Equal(t, 400, e.Status)
	})

	t.Run("error while calling GetClients", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)
		mocks.keycloakClient.EXPECT().GetClients(accessToken, realmID).Return([]kc.ClientRepresentation{}, errors.New("error"))
		err := managementComponent.UpdateRealmCustomConfiguration(ctx, realmID, configInit)

		assert.NotNil(t, err)
	})

	t.Run("error while calling GetRealm", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kc.RealmRepresentation{}, errors.New("error"))
		err := managementComponent.UpdateRealmCustomConfiguration(ctx, realmID, configInit)

		assert.NotNil(t, err)
	})
}

func TestGetRealmAdminConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var realmName = "myrealm"
	var realmID = "1234-5678"
	var accessToken = "acce-ssto-ken"
	var expectedError = errors.New("expectedError")
	var dbAdminConfig configuration.RealmAdminConfiguration
	var apiAdminConfig = api.ConvertRealmAdminConfigurationFromDBStruct(dbAdminConfig)
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Request to Keycloak client fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{}, expectedError)
		var _, err = component.GetRealmAdminConfiguration(ctx, realmName)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Request to database fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, gomock.Any()).Return(dbAdminConfig, expectedError)
		var _, err = component.GetRealmAdminConfiguration(ctx, realmName)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmID).Return(dbAdminConfig, nil)
		var res, err = component.GetRealmAdminConfiguration(ctx, realmName)
		assert.Nil(t, err)
		assert.Equal(t, apiAdminConfig, res)
	})
}

func TestUpdateRealmAdminConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var realmName = "myrealm"
	var realmID = "1234-5678"
	var accessToken = "acce-ssto-ken"
	var expectedError = errors.New("expectedError")
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)
	var adminConfig api.RealmAdminConfiguration

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Request to Keycloak client fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{}, expectedError)
		var err = component.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Request to database fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().StoreOrUpdateAdminConfiguration(ctx, realmID, gomock.Any()).Return(expectedError)
		var err = component.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().StoreOrUpdateAdminConfiguration(ctx, realmID, gomock.Any()).Return(nil)
		var err = component.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Nil(t, err)
	})
}

func createBackOfficeConfiguration(JSON string) dto.BackOfficeConfiguration {
	var conf dto.BackOfficeConfiguration
	_ = json.Unmarshal([]byte(JSON), &conf)
	return conf
}

func TestRealmBackOfficeConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var realmID = "master_id"
	var groupName = "the.group"
	var config = api.BackOfficeConfiguration{}
	var ctx = context.WithValue(context.TODO(), cs.CtContextGroups, []string{"grp1", "grp2"})
	var largeConf = `
		{
			"realm1": {
				"a": [ "grp1" ]
			},
			"realm2": {
				"a": [ "grp1" ],
				"b": [ "grp2" ],
				"c": [ "grp1", "grp2" ]
			}
		}
	`
	var smallConf = `
		{
			"realm2": {
				"a": [ "grp1" ],
				"c": [ "grp2" ]
			}
		}
	`

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("UpdateRealmBackOfficeConfiguration - db.GetBackOfficeConfiguration fails", func(t *testing.T) {
		var expectedError = errors.New("db error")
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(nil, expectedError)
		var err = component.UpdateRealmBackOfficeConfiguration(ctx, realmID, groupName, config)
		assert.Equal(t, expectedError, err)
	})

	t.Run("UpdateRealmBackOfficeConfiguration - remove items", func(t *testing.T) {
		var dbConf = createBackOfficeConfiguration(largeConf)
		var requestConf, _ = api.NewBackOfficeConfigurationFromJSON(smallConf)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, nil)
		mocks.configurationDBModule.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, "realm1", nil, nil).Return(nil)
		mocks.configurationDBModule.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, "realm2", gomock.Not(nil), nil).Return(nil)
		mocks.configurationDBModule.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, "realm2", gomock.Not(nil), gomock.Not(nil)).Return(nil)
		var err = component.UpdateRealmBackOfficeConfiguration(ctx, realmID, groupName, requestConf)
		assert.Nil(t, err)
	})

	t.Run("UpdateRealmBackOfficeConfiguration - add items", func(t *testing.T) {
		var dbConf = createBackOfficeConfiguration(smallConf)
		var requestConf, _ = api.NewBackOfficeConfigurationFromJSON(largeConf)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, nil)
		mocks.configurationDBModule.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, "realm1", "a", []string{"grp1"}).Return(nil)
		mocks.configurationDBModule.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, "realm2", "b", []string{"grp2"}).Return(nil)
		mocks.configurationDBModule.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, "realm2", "c", []string{"grp1"}).Return(nil)
		var err = component.UpdateRealmBackOfficeConfiguration(ctx, realmID, groupName, requestConf)
		assert.Nil(t, err)
	})

	t.Run("GetRealmBackOfficeConfiguration - error", func(t *testing.T) {
		var dbConf = createBackOfficeConfiguration(smallConf)
		var expectedError = errors.New("db error")
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, expectedError)
		var res, err = component.GetRealmBackOfficeConfiguration(ctx, realmID, groupName)
		assert.Equal(t, expectedError, err)
		assert.Nil(t, res)
	})

	t.Run("GetRealmBackOfficeConfiguration - success", func(t *testing.T) {
		var dbConf = createBackOfficeConfiguration(smallConf)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, nil)
		var res, err = component.GetRealmBackOfficeConfiguration(ctx, realmID, groupName)
		assert.Nil(t, err)
		assert.Equal(t, api.BackOfficeConfiguration(dbConf), res)
	})

	t.Run("GetUserRealmBackOfficeConfiguration - db error", func(t *testing.T) {
		var dbError = errors.New("db error")
		var groups = ctx.Value(cs.CtContextGroups).([]string)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, groups).Return(nil, dbError)
		var _, err = component.GetUserRealmBackOfficeConfiguration(ctx, realmID)
		assert.Equal(t, dbError, err)
	})

	t.Run("GetUserRealmBackOfficeConfiguration - success", func(t *testing.T) {
		var dbConf = createBackOfficeConfiguration(smallConf)
		var groups = ctx.Value(cs.CtContextGroups).([]string)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, groups).Return(dbConf, nil)
		var res, err = component.GetUserRealmBackOfficeConfiguration(ctx, realmID)
		assert.Nil(t, err)
		assert.Equal(t, api.BackOfficeConfiguration(dbConf), res)
	})
}

func TestGetFederatedIdentities(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var username = "username"
	var idpName = "idpName"
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	t.Run("Call to keycloak fails", func(t *testing.T) {
		var anyError = errors.New("any error")
		mocks.logger.EXPECT().Warn(ctx, gomock.Any())
		mocks.keycloakClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return(nil, anyError)
		var _, err = managementComponent.GetFederatedIdentities(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Success - Result is empty", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return([]kc.FederatedIdentityRepresentation{}, nil)
		var res, err = managementComponent.GetFederatedIdentities(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res, 0)
	})
	t.Run("Success - Result is not empty", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return([]kc.FederatedIdentityRepresentation{
			{UserID: &userID, UserName: &username, IdentityProvider: &idpName},
		}, nil)
		var res, err = managementComponent.GetFederatedIdentities(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Len(t, res, 1)
		assert.Equal(t, userID, *res[0].UserID)
		assert.Equal(t, username, *res[0].Username)
		assert.Equal(t, idpName, *res[0].IdentityProvider)
	})
}

func TestLinkShadowUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var username = "test"
	var realmName = "master"
	var userID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var provider = "provider"

	// Create shadow user
	t.Run("Create shadow user successfully", func(t *testing.T) {
		fedIDKC := kc.FederatedIdentityRepresentation{UserName: &username, UserID: &userID}
		fedID := api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}

		mocks.keycloakClient.EXPECT().LinkShadowUser(accessToken, realmName, userID, provider, fedIDKC).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		err := managementComponent.LinkShadowUser(ctx, realmName, userID, provider, fedID)

		assert.Nil(t, err)
	})

	// Error from KC client
	t.Run("Create shadow user - error at KC client", func(t *testing.T) {
		fedIDKC := kc.FederatedIdentityRepresentation{UserName: &username, UserID: &userID}
		fedID := api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}

		mocks.keycloakClient.EXPECT().LinkShadowUser(accessToken, realmName, userID, provider, fedIDKC).Return(fmt.Errorf("error"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.logger.EXPECT().Warn(ctx, gomock.Any())
		err := managementComponent.LinkShadowUser(ctx, realmName, userID, provider, fedID)

		assert.NotNil(t, err)
	})
}

func TestGetIdentityProviders(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "test"

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	t.Run("Get identity providers success", func(t *testing.T) {
		kcIdp := kc.IdentityProviderRepresentation{
			AddReadTokenRoleOnCreate:  ptrBool(false),
			Alias:                     ptr("testIDP"),
			AuthenticateByDefault:     ptrBool(false),
			Config:                    &map[string]interface{}{},
			DisplayName:               ptr("TEST"),
			Enabled:                   ptrBool(false),
			FirstBrokerLoginFlowAlias: ptr("first broker login"),
			InternalID:                ptr("0da3e7b1-6a99-4f73-92aa-86be96f4c2c5"),
			LinkOnly:                  ptrBool(false),
			PostBrokerLoginFlowAlias:  ptr("post broker login"),
			ProviderID:                ptr("oidc"),
			StoreToken:                ptrBool(false),
			TrustEmail:                ptrBool(false),
		}
		mocks.keycloakClient.EXPECT().GetIdps(accessToken, realmName).Return([]kc.IdentityProviderRepresentation{kcIdp}, nil)

		res, err := managementComponent.GetIdentityProviders(ctx, realmName)
		assert.Nil(t, err)
		assert.Len(t, res, 1)
	})
	t.Run("Get identity providers success-empty result", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetIdps(accessToken, realmName).Return(nil, nil)

		res, err := managementComponent.GetIdentityProviders(ctx, realmName)
		assert.Nil(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res, 0)
		var bytes, _ = json.Marshal(res)
		assert.Equal(t, "[]", string(bytes))
	})
	t.Run("Get identity providers error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetIdps(accessToken, realmName).Return([]kc.IdentityProviderRepresentation{}, errors.New("error"))

		_, err := managementComponent.GetIdentityProviders(ctx, realmName)
		assert.NotNil(t, err)
	})
}
