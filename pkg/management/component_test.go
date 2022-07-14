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
	"github.com/cloudtrust/common-service/v2/database"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	csjson "github.com/cloudtrust/common-service/v2/json"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	keycloakClient        *mock.KeycloakClient
	usersDetailsDBModule  *mock.UsersDetailsDBModule
	eventDBModule         *mock.EventDBModule
	configurationDBModule *mock.ConfigurationDBModule
	onboardingModule      *mock.OnboardingModule
	authChecker           *mock.AuthorizationManager
	tokenProvider         *mock.OidcTokenProvider
	transaction           *mock.Transaction
	glnVerifier           *mock.GlnVerifier
	logger                *mock.Logger
}

func createMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		keycloakClient:        mock.NewKeycloakClient(mockCtrl),
		usersDetailsDBModule:  mock.NewUsersDetailsDBModule(mockCtrl),
		eventDBModule:         mock.NewEventDBModule(mockCtrl),
		configurationDBModule: mock.NewConfigurationDBModule(mockCtrl),
		onboardingModule:      mock.NewOnboardingModule(mockCtrl),
		authChecker:           mock.NewAuthorizationManager(mockCtrl),
		tokenProvider:         mock.NewOidcTokenProvider(mockCtrl),
		transaction:           mock.NewTransaction(mockCtrl),
		glnVerifier:           mock.NewGlnVerifier(mockCtrl),
		logger:                mock.NewLogger(mockCtrl),
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
	return NewComponent(m.keycloakClient, nil, m.usersDetailsDBModule, m.eventDBModule, m.configurationDBModule, m.onboardingModule,
		m.authChecker, m.tokenProvider, allowedTrustIDGroups, socialRealmName, m.glnVerifier, m.logger).(*component)
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
	// We add 3 here, as we added the three actions from the communications & tasks stacks into the GetActions methods of the component.
	// We did this to be able to configure those actions through the Backoffice.
	assert.Equal(t, len(actions)+3, len(res))
	v, s := "COM_SendEmail", string(security.ScopeRealm)
	assert.Contains(t, res, api.ActionRepresentation{Name: &v, Scope: &s})
	v, s = "COM_SendSMS", string(security.ScopeRealm)
	assert.Contains(t, res, api.ActionRepresentation{Name: &v, Scope: &s})
	v, s = "TSK_DeleteDeniedToUUsers", string(security.ScopeGlobal)
	assert.Contains(t, res, api.ActionRepresentation{Name: &v, Scope: &s})
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

		mocks.eventDBModule.EXPECT().Store(ctx, gomock.Any()).Return(nil).AnyTimes()

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

		mocks.eventDBModule.EXPECT().Store(ctx, gomock.Any()).Return(nil).AnyTimes()

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
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Invalid GLN provided", func(t *testing.T) {
		var businessID = "123456789"

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, socialRealmName).Return(configuration.RealmAdminConfiguration{}, anyError)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any())

		_, err := managementComponent.CreateUser(ctx, socialRealmName, api.UserRepresentation{BusinessID: &businessID}, false, false, false)

		assert.Equal(t, anyError, err)
	})
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(gomock.Any(), gomock.Any()).Return(configuration.RealmAdminConfiguration{}, nil).AnyTimes()

	t.Run("Create user with username generation, don't need terms of use", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, realmName, socialRealmName, gomock.Any()).
			DoAndReturn(func(_, _, _, _ interface{}, user *kc.UserRepresentation) (string, error) {
				assert.NotNil(t, user)
				assert.Nil(t, user.RequiredActions)
				return "", anyError
			})
		mocks.logger.EXPECT().Warn(ctx, "err", gomock.Any())

		_, err := managementComponent.CreateUser(ctx, socialRealmName, api.UserRepresentation{}, false, false, false)

		assert.Equal(t, anyError, err)
	})
	t.Run("Create user with username generation, need terms of use", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, realmName, socialRealmName, gomock.Any()).
			DoAndReturn(func(_, _, _, _ interface{}, user *kc.UserRepresentation) (string, error) {
				assert.NotNil(t, user)
				assert.NotNil(t, user.RequiredActions)
				assert.Len(t, *user.RequiredActions, 1)
				assert.Equal(t, (*user.RequiredActions)[0], "ct-terms-of-use")
				return "", anyError
			})
		mocks.logger.EXPECT().Warn(ctx, "err", gomock.Any())

		_, err := managementComponent.CreateUser(ctx, socialRealmName, api.UserRepresentation{}, false, false, true)

		assert.Equal(t, anyError, err)
	})

	var attrbs = make(kc.Attributes)
	attrbs[constants.AttrbSource] = []string{"api"}
	t.Run("Create with minimum properties", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrbs,
		}

		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, kcUserRep).Return(locationURL, nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ACCOUNT_CREATION", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		var userRep = api.UserRepresentation{
			Username: &username,
		}

		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, false, false)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Create with minimum properties and having error when storing the event", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrbs,
		}

		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, realmName, kcUserRep).Return(locationURL, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ACCOUNT_CREATION", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, username).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "API_ACCOUNT_CREATION", database.CtEventRealmName: realmName, database.CtEventUserID: userID, database.CtEventUsername: username}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))

		var userRep = api.UserRepresentation{
			Username: &username,
		}

		location, err := managementComponent.CreateUser(ctx, realmName, userRep, false, false, false)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

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

		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, targetRealmName string, kcUserRep kc.UserRepresentation) (string, error) {
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
				assert.NotNil(t, kcUserRep.GetAttributeString(constants.AttrbNameID))
				return locationURL, nil
			})

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.usersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).DoAndReturn(
			func(ctx context.Context, targetRealmName string, user dto.DBUser) {
				assert.Equal(t, userID, *user.UserID)
				assert.Equal(t, birthLocation, *user.BirthLocation)
				assert.Equal(t, nationality, *user.Nationality)
				assert.Equal(t, idDocumentType, *user.IDDocumentType)
				assert.Equal(t, idDocumentNumber, *user.IDDocumentNumber)
				assert.Equal(t, idDocumentExpiration, *user.IDDocumentExpiration)
				assert.Equal(t, idDocumentCountry, *user.IDDocumentCountry)
			}).Return(nil)

		mocks.eventDBModule.EXPECT().Store(ctx, gomock.Any()).Return(nil).AnyTimes()

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
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ACCOUNT_CREATION", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, true, false)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			Attributes: &attrbs,
		}

		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, kcUserRep).Return("", fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		var userRep = api.UserRepresentation{}
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, false, false)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	})

	t.Run("Error from DB users", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, targetRealmName string, kcUserRep kc.UserRepresentation) (string, error) {
				return locationURL, nil
			})

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		mocks.usersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(fmt.Errorf("SQL error"))

		var birthLocation = "Rolle"
		var userRep = api.UserRepresentation{
			ID:            &userID,
			Username:      &username,
			BirthLocation: &birthLocation,
		}
		mocks.logger.EXPECT().Warn(ctx, "msg", "Can't store user details in database", "err", "SQL error")

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
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(gomock.Any(), managementComponent.socialRealmName).Return(configuration.RealmAdminConfiguration{}, nil).AnyTimes()

	t.Run("Can't get JWT token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)

		_, err := managementComponent.CreateUserInSocialRealm(ctx, userRep, false)
		assert.Equal(t, anyError, err)
	})
	t.Run("Process already existing user cases calls handler", func(t *testing.T) {
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

func TestCheckGLN(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var realmName = "my-realm"
	var gln = "123456789"
	var firstName = "first"
	var lastName = "last"
	var kcUser = kc.UserRepresentation{FirstName: &firstName, LastName: &lastName}
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, realmName)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetRealmAdminConfiguration fails", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{}, anyError)

		var err = managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("GLN feature not activated", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{}, nil)

		var err = managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.Nil(t, err)
		assert.Nil(t, kcUser.GetAttributeString(constants.AttrbBusinessID))
	})

	var bTrue = true
	var confWithGLN = configuration.RealmAdminConfiguration{ShowGlnEditing: &bTrue}
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(confWithGLN, nil).AnyTimes()

	t.Run("Removing GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		var err = managementComponent.checkGLN(ctx, realmName, true, nil, &kcUser)
		assert.Nil(t, err)
		assert.Nil(t, kcUser.GetAttributeString(constants.AttrbBusinessID))
	})
	t.Run("Using invalid GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.glnVerifier.EXPECT().ValidateGLN(firstName, lastName, gln).Return(anyError)

		var err = managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("Using valid GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.glnVerifier.EXPECT().ValidateGLN(firstName, lastName, gln).Return(nil)

		var err = managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.Nil(t, err)
	})
	t.Run("No change asked for GLN field", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		var err = managementComponent.checkGLN(ctx, realmName, false, nil, &kcUser)
		assert.Nil(t, err)
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
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.usersDetailsDBModule.EXPECT().DeleteUserDetails(ctx, realmName, userID).Return(nil)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ACCOUNT_DELETION", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.DeleteUser(ctx, "master", userID)

		assert.Nil(t, err)
	})

	t.Run("Delete user with success but the having an error when storing the event in the DB", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.usersDetailsDBModule.EXPECT().DeleteUserDetails(ctx, realmName, userID).Return(nil)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ACCOUNT_DELETION", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, userID).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "API_ACCOUNT_DELETION", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))
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

	t.Run("Error from DB users", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.usersDetailsDBModule.EXPECT().DeleteUserDetails(ctx, realmName, userID).Return(fmt.Errorf("SQL Error"))

		mocks.logger.EXPECT().Warn(ctx, "err", "SQL Error")

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
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dto.DBUser{
			UserID:               &id,
			BirthLocation:        &birthLocation,
			Nationality:          &nationality,
			IDDocumentExpiration: &idDocumentExpiration,
			IDDocumentNumber:     &idDocumentNumber,
			IDDocumentType:       &idDocumentType,
			IDDocumentCountry:    &idDocumentCountry,
		}, nil)

		mocks.usersDetailsDBModule.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]dto.DBCheck{{
			Nature:   ptr("nature"),
			Status:   ptr("PENDING"),
			DateTime: &now,
		}}, nil)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "GET_DETAILS", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dto.DBUser{
			UserID: &id,
		}, nil)
		mocks.usersDetailsDBModule.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]dto.DBCheck{{
			Nature:   ptr("nature"),
			Status:   ptr("PENDING"),
			DateTime: &now,
		}}, nil)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "GET_DETAILS", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
	})

	t.Run("Get user with succces but with error when storing the event in the DB", func(t *testing.T) {
		var birthLocation = "Rolle"
		var nationality = "CH"
		var idDocumentType = "Card ID"
		var idDocumentNumber = "1234-4567-VD-3"
		var idDocumentExpiration = "23.12.2019"
		var now = time.Now().UTC()
		var idDocumentCountry = "BE"
		var kcUserRep = kc.UserRepresentation{
			ID:       &id,
			Username: &username,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dto.DBUser{
			UserID:               &id,
			BirthLocation:        &birthLocation,
			Nationality:          &nationality,
			IDDocumentExpiration: &idDocumentExpiration,
			IDDocumentNumber:     &idDocumentNumber,
			IDDocumentType:       &idDocumentType,
			IDDocumentCountry:    &idDocumentCountry,
		}, nil)
		mocks.usersDetailsDBModule.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]dto.DBCheck{{
			Nature:   ptr("nature"),
			Status:   ptr("PENDING"),
			DateTime: &now,
		}}, nil)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "GET_DETAILS", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, id, database.CtEventUsername, username).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "GET_DETAILS", database.CtEventRealmName: realmName, database.CtEventUserID: id, database.CtEventUsername: username}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))

		apiUserRep, err := managementComponent.GetUser(ctx, "master", id)
		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
	})

	t.Run("Error with Users DB", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			ID:       &id,
			Username: &username,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dto.DBUser{}, fmt.Errorf("SQL Error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "SQL Error")

		_, err := managementComponent.GetUser(ctx, "master", id)

		assert.NotNil(t, err)
	})

	t.Run("Retrieve checks fails", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			ID:       &id,
			Username: &username,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dto.DBUser{}, nil)
		mocks.usersDetailsDBModule.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]dto.DBCheck{}, fmt.Errorf("SQL Error"))
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

	var accessToken = "TOKEN=="
	var realmName = "master"
	var id = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var enabled = true
	var disabled = false

	var birthLocation = "Rolle"
	var nationality = "CH"
	var idDocumentType = "Card ID"
	var idDocumentNumber = "1234-4567-VD-3"
	var idDocumentExpiration = "23.12.2019"
	var idDocumentCountry = "CH"
	var createdTimestamp = time.Now().UTC().Unix()
	var anyError = errors.New("any error")
	var userRep = createUpdateUser()

	var attributes = make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, *userRep.PhoneNumber.Value)
	attributes.SetString(constants.AttrbLabel, *userRep.Label)
	attributes.SetString(constants.AttrbGender, *userRep.Gender)
	attributes.SetString(constants.AttrbBirthDate, *userRep.BirthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
	attributes.SetString(constants.AttrbLocale, *userRep.Locale)

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

	var dbUserRep = dto.DBUser{
		UserID:               &id,
		BirthLocation:        &birthLocation,
		Nationality:          &nationality,
		IDDocumentType:       &idDocumentType,
		IDDocumentNumber:     &idDocumentNumber,
		IDDocumentExpiration: &idDocumentExpiration,
		IDDocumentCountry:    &idDocumentCountry,
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, *userRep.Username)

	t.Run("Update user in realm with self register enabled", func(t *testing.T) {
		var newUsername = "new-username"
		var userWithNewUsername = createUpdateUser()
		userWithNewUsername.Username = &newUsername

		mocks.keycloakClient.EXPECT().GetUser(accessToken, socialRealmName, id).Return(kcUserRep, nil)
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, socialRealmName, id).Return(dbUserRep, nil)
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
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)

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

		err := managementComponent.UpdateUser(ctx, "master", id, userRep)

		assert.Nil(t, err)
	})

	t.Run("Update user with succces (with user info update)", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil).Times(2)
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil).Times(2)

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

		mocks.usersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).DoAndReturn(
			func(ctx context.Context, realm string, user dto.DBUser) error {
				assert.Equal(t, id, *user.UserID)
				assert.Equal(t, birthLocation, *user.BirthLocation)
				assert.Equal(t, nationality, *user.Nationality)
				assert.Equal(t, idDocumentType, *user.IDDocumentType)
				assert.Equal(t, idDocumentNumber, *user.IDDocumentNumber)
				assert.Equal(t, newIDDocumentExpiration, *user.IDDocumentExpiration)
				assert.Equal(t, idDocumentCountry, *user.IDDocumentCountry)
				return nil
			})

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

		mocks.usersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).DoAndReturn(
			func(ctx context.Context, realm string, user dto.DBUser) error {
				assert.Equal(t, id, *user.UserID)
				assert.Equal(t, newBirthLocation, *user.BirthLocation)
				assert.Equal(t, newNationality, *user.Nationality)
				assert.Equal(t, newIDDocumentType, *user.IDDocumentType)
				assert.Equal(t, newIDDocumentNumber, *user.IDDocumentNumber)
				assert.Equal(t, newIDDocumentExpiration, *user.IDDocumentExpiration)
				assert.Equal(t, newIDDocumentCountry, *user.IDDocumentCountry)
				return nil
			})

		err = managementComponent.UpdateUser(ctx, realmName, id, userAPI)
		assert.Nil(t, err)
	})

	t.Run("Update by locking the user", func(t *testing.T) {
		kcUserRep.Enabled = &enabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "LOCK_ACCOUNT", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.UpdateUser(ctx, "master", id, userRepLocked)

		assert.Nil(t, err)
	})

	t.Run("Update to unlock the user", func(t *testing.T) {
		kcUserRep.Enabled = &disabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)

		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).Return(nil)

		var userRepLocked = createUpdateUser()
		userRepLocked.Enabled = &enabled

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "UNLOCK_ACCOUNT", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, *userRep.Email.Value, *kcUserRep.Email)
				assert.Equal(t, false, *kcUserRep.EmailVerified)
				return nil
			})

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
		var withoutEmailUser = userRep
		withoutEmailUser.Email = csjson.OptionalString{Defined: true, Value: nil}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(oldkcUserRep, nil)
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, "", *kcUserRep.Email)
				assert.Equal(t, false, *kcUserRep.EmailVerified)
				return nil
			})

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
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, *userRep.PhoneNumber.Value, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, false, *verified)
				return nil
			})

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
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				_, ok := (*kcUserRep.Attributes)[constants.AttrbPhoneNumber]
				assert.False(t, ok)
				_, ok = (*kcUserRep.Attributes)[constants.AttrbPhoneNumberVerified]
				assert.False(t, ok)
				return nil
			})

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
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, oldNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, true, *verified)
				return nil
			})

		err := managementComponent.UpdateUser(ctx, "master", id, userRepWithoutAttr)

		assert.Nil(t, err)
	})

	t.Run("Update user with succces but with error when storing the event in the DB", func(t *testing.T) {
		var kcUserRep = kc.UserRepresentation{
			ID:       &id,
			Username: userRep.Username,
			Enabled:  &disabled,
		}

		var userRep = api.UpdatableUserRepresentation{
			Username: userRep.Username,
			Enabled:  &enabled,
		}

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, *userRep.Username)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "UNLOCK_ACCOUNT", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, id, database.CtEventUsername, *userRep.Username).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "UNLOCK_ACCOUNT", database.CtEventRealmName: realmName, database.CtEventUserID: id, database.CtEventUsername: *userRep.Username}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).Return(nil)

		err := managementComponent.UpdateUser(ctx, "master", id, userRep)

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

	t.Run("Error - get user info from DB", func(t *testing.T) {
		var id = "1234-79894-7594"
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kc.UserRepresentation{}, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dto.DBUser{}, fmt.Errorf("SQL Error"))

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
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).Return(fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Unexpected error")

		err := managementComponent.UpdateUser(ctx, "master", id, api.UpdatableUserRepresentation{})

		assert.NotNil(t, err)
	})

	t.Run("Error - update user info in DB", func(t *testing.T) {
		var id = "1234-79894-7594"
		var kcUserRep = kc.UserRepresentation{
			ID: &id,
		}
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil).AnyTimes()
		mocks.usersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, id).Return(dbUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).Return(nil)
		mocks.usersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).Return(fmt.Errorf("SQL error"))
		mocks.logger.EXPECT().Warn(gomock.Any(), "msg", "Can't store user details in database", "err", "SQL error")

		var newIDDocumentType = "Visa"
		err := managementComponent.UpdateUser(ctx, realmName, id, api.UpdatableUserRepresentation{
			IDDocumentExpiration: &newIDDocumentType,
		})

		assert.NotNil(t, err)
	})
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
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "LOCK_ACCOUNT", "back-office", gomock.Any()).Return(nil)
		var err = managementComponent.LockUser(ctx, realmName, userID)
		assert.Nil(t, err)
	})
	t.Run("Unlock success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bFalse}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "UNLOCK_ACCOUNT", "back-office", gomock.Any()).Return(nil)
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
		mocks.usersDetailsDBModule.EXPECT().GetChecks(ctx, realmName, userID).Return(nil, errors.New("db error"))
		_, err := managementComponent.GetUserChecks(ctx, realmName, userID)
		assert.NotNil(t, err)
	})
	t.Run("GetChecks returns a check", func(t *testing.T) {
		var operator = "The Operator"
		var dbCheck = dto.DBCheck{
			Operator: &operator,
		}
		var dbChecks = []dto.DBCheck{dbCheck, dbCheck}
		mocks.usersDetailsDBModule.EXPECT().GetChecks(ctx, realmName, userID).Return(dbChecks, nil)
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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "INIT_PASSWORD", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		var passwordRep = api.PasswordRepresentation{
			Value: &password,
		}

		_, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
	})
	t.Run("Change password but with error when storing the DB", func(t *testing.T) {
		var kcCredRep = kc.CredentialRepresentation{
			Type:  &typePassword,
			Value: &password,
		}

		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, kcCredRep).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "INIT_PASSWORD", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, userID).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "INIT_PASSWORD", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(gomock.Any(), "err", "error", "event", string(eventJSON))
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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "INIT_PASSWORD", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "INIT_PASSWORD", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "CREATE_RECOVERY_CODE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "CREATE_ACTIVATION_CODE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "INIT_PASSWORD", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions, key1, value1, key2, value2)

		assert.Nil(t, err)
	})
	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions).Return(fmt.Errorf("Invalid input"))

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "INIT_PASSWORD", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions)

		assert.NotNil(t, err)
	})
	t.Run("Send email actions, but not sms-password-set", func(t *testing.T) {
		var actions2 = []string{"action1", "action2"}
		var reqActions2 = []api.RequiredAction{"action1", "action2"}
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions2, key1, value1, key2, value2).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
	var kcUser = kc.UserRepresentation{
		ID: &userID,
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
	var userID = "1245-7854-8963"

	t.Run("Send new sms code", func(t *testing.T) {
		var code = "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, realmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "SMS_CHALLENGE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		codeRes, err := managementComponent.SendSmsCode(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, "1234", codeRes)
	})
	t.Run("Send new sms code but have error when storing the event in the DB", func(t *testing.T) {
		var code = "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, realmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "SMS_CHALLENGE", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, userID).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "SMS_CHALLENGE", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(gomock.Any(), "err", "error", "event", string(eventJSON))
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

		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, realmName, userID, username,
			onboardingClientID, onboardingRedirectURI+"?customerRealm="+customerRealmName, customerRealmName, true).Return(anyError)

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
		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, gomock.Any(), false).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "EMAIL_ONBOARDING_SENT", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, userID).Return(nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "2ND_FACTOR_REMOVED", "back-office", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

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

	t.Run("Error at storing the event", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{credMfa1, credMfa2}, nil)
		mocks.keycloakClient.EXPECT().DeleteCredential(accessToken, realmName, userID, *credMfa1.ID).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "2ND_FACTOR_REMOVED", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error"))

		err := managementComponent.DeleteCredentialsForUser(ctx, realmName, userID, *credMfa1.ID)

		assert.Nil(t, err)
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
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "LOGIN_FAILURE_CLEARED", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ROLE_CREATION", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		var roleRep = api.RoleRepresentation{
			Name: &name,
		}

		location, err := managementComponent.CreateRole(ctx, realmName, roleRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Create with having error when storing the event", func(t *testing.T) {
		var kcRoleRep = kc.RoleRepresentation{
			Name:       &name,
			Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}},
		}

		mocks.keycloakClient.EXPECT().CreateRole(accessToken, realmName, kcRoleRep).Return(locationURL, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ROLE_CREATION", "back-office", database.CtEventRealmName, realmName, database.CtEventRoleID, roleID, database.CtEventRoleName, name).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "API_ROLE_CREATION", database.CtEventRealmName: realmName, database.CtEventRoleID: roleID, database.CtEventRoleName: name}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))

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
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ROLE_UPDATE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ROLE_DELETION", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.DeleteRole(ctx, realmName, roleID)

		assert.Nil(t, err)
	})

	t.Run("Delete role with success but having an error when storing the event in the DB", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().DeleteRole(accessToken, realmName, roleID).Return(nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_ROLE_DELETION", "back-office", database.CtEventRealmName, realmName, database.CtEventRoleName, roleName).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "API_ROLE_DELETION", database.CtEventRealmName: realmName, database.CtEventRoleName: roleName}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))
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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_GROUP_CREATION", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		var groupRep = api.GroupRepresentation{
			Name: &name,
		}

		location, err := managementComponent.CreateGroup(ctx, targetRealmName, groupRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Create with having error when storing the event", func(t *testing.T) {
		var kcGroupRep = kc.GroupRepresentation{
			Name: &name,
		}

		mocks.keycloakClient.EXPECT().CreateGroup(accessToken, targetRealmName, kcGroupRep).Return(locationURL, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_GROUP_CREATION", "back-office", database.CtEventRealmName, targetRealmName, database.CtEventGroupID, groupID, database.CtEventGroupName, name).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "API_GROUP_CREATION", database.CtEventRealmName: targetRealmName, database.CtEventGroupID: groupID, database.CtEventGroupName: name}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))

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

		mocks.configurationDBModule.EXPECT().DeleteAllAuthorizationsWithGroup(ctx, targetRealmName, groupName).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_GROUP_DELETION", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.DeleteGroup(ctx, targetRealmName, groupID)

		assert.Nil(t, err)
	})

	t.Run("Delete group with success but having an error when storing the event in the DB", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroup(accessToken, targetRealmName, groupID).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.configurationDBModule.EXPECT().DeleteAllAuthorizationsWithGroup(ctx, targetRealmName, groupName).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_GROUP_DELETION", "back-office", database.CtEventRealmName, targetRealmName, database.CtEventGroupName, groupName).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "API_GROUP_DELETION", database.CtEventRealmName: targetRealmName, database.CtEventGroupName: groupName}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))
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

	t.Run("Call to Keycloak.GetGroup fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(kc.GroupRepresentation{}, errors.New("Error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Call to Keycloak GetRealm fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return([]kc.RealmRepresentation{}, fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Call to Keycloak GetGroups fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return([]kc.GroupRepresentation{}, fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to create transaction", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(nil, fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to delete existing authorizations", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.transaction.EXPECT().Close()
		mocks.configurationDBModule.EXPECT().DeleteAuthorizations(ctx, targetRealmName, groupName).Return(fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to create new authorizations", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.transaction.EXPECT().Close()
		mocks.configurationDBModule.EXPECT().DeleteAuthorizations(ctx, targetRealmName, groupName).Return(nil)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, gomock.Any()).Return(fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Persists in DB: fails to commit transaction", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.configurationDBModule.EXPECT().DeleteAuthorizations(ctx, targetRealmName, groupName).Return(nil)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, gomock.Any()).Return(nil)
		mocks.transaction.EXPECT().Close()
		mocks.transaction.EXPECT().Commit().Return(fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.configurationDBModule.EXPECT().DeleteAuthorizations(ctx, targetRealmName, groupName).Return(nil)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, gomock.Any()).Return(nil)
		mocks.transaction.EXPECT().Close()
		mocks.transaction.EXPECT().Commit()
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_AUTHORIZATIONS_UPDATE", "back-office", database.CtEventRealmName, targetRealmName, database.CtEventGroupName, groupName).Return(errors.New("error"))
		m := map[string]interface{}{"event_name": "API_AUTHORIZATIONS_UPDATE", database.CtEventRealmName: targetRealmName, database.CtEventGroupName: groupName}
		eventJSON, _ := json.Marshal(m)
		mocks.logger.EXPECT().Error(ctx, "err", "error", "event", string(eventJSON))

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
		mocks.logger.EXPECT().Warn(ctx, "err", gomock.Any())
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.NotNil(t, err)
	})
}

func TestUpdateAuthorizationsWithAny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var managementComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var currentRealmName = "master"
	var targetRealmName = "DEP"
	var targetMasterRealmName = "master"
	var groupID = "41dbf4a8-32a9-4000-8c17-edc854c31231"
	var groupName = "groupName"
	var username = "username"

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	var groups = []kc.GroupRepresentation{}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Check * as target realm is forbidden for non master realm", func(t *testing.T) {
		var action = "action"
		var matrix = map[string]map[string]map[string]struct{}{
			action: {"*": {}},
		}

		var apiAuthorizations = api.AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		var realm = kc.RealmRepresentation{
			ID:    &targetRealmName,
			Realm: &targetRealmName,
		}
		var realms = []kc.RealmRepresentation{realm}

		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.logger.EXPECT().Warn(ctx, "err", gomock.Any())

		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)

		assert.NotNil(t, err)
	})

	t.Run("Check * as target realm is allowed for master realm", func(t *testing.T) {
		var action = "action"
		var matrix = map[string]map[string]map[string]struct{}{
			action: {"*": {}},
		}

		var apiAuthorizations = api.AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		var realm = kc.RealmRepresentation{
			ID:    &targetMasterRealmName,
			Realm: &targetMasterRealmName,
		}
		var realms = []kc.RealmRepresentation{realm}

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, targetMasterRealmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetMasterRealmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(realms, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetMasterRealmName).Return(groups, nil)

		mocks.configurationDBModule.EXPECT().NewTransaction(ctx).Return(mocks.transaction, nil)
		mocks.configurationDBModule.EXPECT().DeleteAuthorizations(ctx, targetMasterRealmName, groupName).Return(nil)
		mocks.configurationDBModule.EXPECT().CreateAuthorization(ctx, gomock.Any()).Return(nil)
		mocks.transaction.EXPECT().Close()
		mocks.transaction.EXPECT().Commit()

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_AUTHORIZATIONS_UPDATE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.UpdateAuthorizations(ctx, targetMasterRealmName, groupID, apiAuthorizations)

		assert.Nil(t, err)
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
	var targetGroupId = "124352"
	var action = "MGMT_DeleteUser"
	var actionRealm = "MGMT_GetRealm"
	var username = "username"
	var star = "*"

	var expectedErr = errors.New("test error")

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	var groups = []kc.GroupRepresentation{
		{
			ID:   &targetGroupId,
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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_AUTHORIZATIONS_PUT", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_AUTHORIZATIONS_PUT", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_AUTHORIZATIONS_PUT", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
	var targetGroupId = "124352"
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
		ID:   &targetGroupId,
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
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, nil).Times(1)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(nil).Times(1)
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)

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
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, nil).Times(1)
		mocks.authChecker.EXPECT().CheckAuthorizationForGroupsOnTargetGroup(realmName, []string{groupName}, action, targetRealmName, targetGroupName).Return(security.ForbiddenError{}).Times(1)
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)

		assert.Nil(t, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - reload failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - group resolution failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, expectedErr).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - target group resolution failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(group, expectedErr).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - validateScope failure", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, nil).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, "UnknownAction")
		assert.NotNil(t, err)
		assert.Equal(t, "400 ."+constants.MsgErrInvalidParam+"."+constants.Authorization+".action", err.Error())
		assert.Equal(t, extpectedAuthzNegativeMsg, authzMsg)
	})

	t.Run("Get authorization - invalid", func(t *testing.T) {
		mocks.authChecker.EXPECT().ReloadAuthorizations(ctx).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil).Times(1)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, nil).Times(1)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())
		authzMsg, err := managementComponent.GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, globalAction)

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
	var targetGroupId = "124352"
	var action = "MGMT_DeleteUser"
	var username = "username"
	var star = "*"

	var expectedErr = errors.New("test error")

	var group = kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	var targetGroup = kc.GroupRepresentation{
		ID:   &targetGroupId,
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

	t.Run("Delete authorization, no parent, no child - SUCCESS", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, *dbAuth.RealmID, *dbAuth.GroupName, *dbAuth.TargetRealmID, gomock.Any(), *dbAuth.Action).Return(true, nil)

		mocks.configurationDBModule.EXPECT().DeleteAuthorization(ctx, realmName, groupName, targetRealmName, gomock.Any(), action)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_AUTHORIZATION_DELETE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)

		assert.Nil(t, err)
	})

	t.Run("Delete global authorization, no parent, no child - SUCCESS", func(t *testing.T) {
		var globalAction = "MGMT_GetActions"
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, realmName, groupName, star, nil, globalAction).Return(true, nil)

		mocks.configurationDBModule.EXPECT().DeleteAuthorization(ctx, realmName, groupName, star, nil, globalAction)

		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "API_AUTHORIZATION_DELETE", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)

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
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, *dbAuth.RealmID, *dbAuth.GroupName, *dbAuth.TargetRealmID, gomock.Any(), *dbAuth.Action).Return(false, expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)

		assert.NotNil(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Delete authorization, delete error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, realmName, groupID).Return(group, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, targetGroupId).Return(targetGroup, nil)
		mocks.configurationDBModule.EXPECT().AuthorizationExists(ctx, *dbAuth.RealmID, *dbAuth.GroupName, *dbAuth.TargetRealmID, gomock.Any(), *dbAuth.Action).Return(true, nil)
		mocks.configurationDBModule.EXPECT().DeleteAuthorization(ctx, realmName, groupName, targetRealmName, gomock.Any(), action).Return(expectedErr)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupId, action)

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
	json.Unmarshal([]byte(JSON), &conf)
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

		mocks.logger.EXPECT().Warn(ctx, "err", "error")
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
