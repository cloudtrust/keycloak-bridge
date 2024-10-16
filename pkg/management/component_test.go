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
	glnVerifier           *mock.GlnVerifier
	logger                *mock.Logger
	accreditationsClient  *mock.AccreditationsServiceClient
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
		glnVerifier:           mock.NewGlnVerifier(mockCtrl),
		logger:                mock.NewLogger(mockCtrl),
		accreditationsClient:  mock.NewAccreditationsServiceClient(mockCtrl),
	}
}

var allowedTrustIDGroups = []string{"grp1", "grp2"}

const (
	socialRealmName = "social"
)

func (m *componentMocks) createComponent() *component {
	/* REMOVE_THIS_3901 : remove second parameter (nil) */
	return NewComponent(m.keycloakClient, nil, m.profileCache, m.eventsReporter, m.configurationDBModule, m.onboardingModule, m.authChecker,
		m.tokenProvider, m.accreditationsClient, allowedTrustIDGroups, socialRealmName, m.glnVerifier, m.logger).(*component)
}

func ptrString(value string) *string {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}

func TestGetActions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	res, err := managementComponent.GetActions(ctx)
	assert.Nil(t, err)

	checkPresence := func(action string, scope security.Scope) {
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get realms with succces", func(t *testing.T) {
		id := "1245"
		keycloakVersion := "4.8.3"
		realm := "master"
		displayName := "Master"
		enabled := true

		kcRealmRep := kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		var kcRealmsRep []kc.RealmRepresentation
		kcRealmsRep = append(kcRealmsRep, kcRealmRep)

		mocks.keycloakClient.EXPECT().GetRealms(accessToken).Return(kcRealmsRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRealmsRep, err := managementComponent.GetRealms(ctx)

		expectedAPIRealmRep := api.RealmRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRealms(ctx)

		assert.NotNil(t, err)
	})
}

func TestGetRealm(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	username := "username"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get realm with succces", func(t *testing.T) {
		id := "1245"
		keycloakVersion := "4.8.3"
		realm := "master"
		displayName := "Master"
		enabled := true

		kcRealmRep := kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kcRealmRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		apiRealmRep, err := managementComponent.GetRealm(ctx, "master")

		expectedAPIRealmRep := api.RealmRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRealm(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestGetClient(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get client with succces", func(t *testing.T) {
		id := "1245-1245-4578"
		name := "clientName"
		baseURL := "http://toto.com"
		clientID := "client-id"
		protocol := "saml"
		enabled := true
		username := "username"

		kcClientRep := kc.ClientRepresentation{
			ID:       &id,
			Name:     &name,
			BaseURL:  &baseURL,
			ClientID: &clientID,
			Protocol: &protocol,
			Enabled:  &enabled,
		}

		mocks.keycloakClient.EXPECT().GetClient(accessToken, realmName, id).Return(kcClientRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		apiClientRep, err := managementComponent.GetClient(ctx, "master", id)

		expectedAPIClientRep := api.ClientRepresentation{
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
		id := "1234-79894-7594"
		mocks.keycloakClient.EXPECT().GetClient(accessToken, realmName, id).Return(kc.ClientRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClient(ctx, "master", id)

		assert.NotNil(t, err)
	})
}

func TestGetClients(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get clients with succces", func(t *testing.T) {
		id := "1234-7894-58"
		name := "clientName"
		baseURL := "http://toto.com"
		clientID := "client-id"
		protocol := "saml"
		enabled := true

		kcClientRep := kc.ClientRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiClientsRep, err := managementComponent.GetClients(ctx, "master")

		expectedAPIClientRep := api.ClientRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClients(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestGetRequiredActions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get required actions with succces", func(t *testing.T) {
		alias := "ALIAS"
		name := "name"
		boolTrue := true
		boolFalse := false

		kcRa := kc.RequiredActionProviderRepresentation{
			Alias:         &alias,
			Name:          &name,
			Enabled:       &boolTrue,
			DefaultAction: &boolTrue,
		}

		kcDisabledRa := kc.RequiredActionProviderRepresentation{
			Alias:         &alias,
			Name:          &name,
			Enabled:       &boolFalse,
			DefaultAction: &boolFalse,
		}

		var kcRasRep []kc.RequiredActionProviderRepresentation
		kcRasRep = append(kcRasRep, kcRa, kcDisabledRa)

		mocks.keycloakClient.EXPECT().GetRequiredActions(accessToken, realmName).Return(kcRasRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRasRep, err := managementComponent.GetRequiredActions(ctx, "master")

		expectedAPIRaRep := api.RequiredActionRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRequiredActions(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestCreateUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	username := "test"
	realmName := "master"
	targetRealmName := "DEP"
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	locationURL := "http://toto.com/realms/" + userID
	anyError := errors.New("any error")
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Invalid GLN provided", func(t *testing.T) {
		businessID := "123456789"

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, socialRealmName).Return(configuration.RealmAdminConfiguration{}, anyError)
		mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any())

		_, err := managementComponent.CreateUser(ctx, socialRealmName, api.UserRepresentation{BusinessID: &businessID}, false, false, false)

		assert.Equal(t, anyError, err)
	})
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(gomock.Any(), gomock.Any()).Return(configuration.RealmAdminConfiguration{}, nil).AnyTimes()

	t.Run("Create user with username generation, don't need terms of use", func(t *testing.T) {
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

	attrbs := make(kc.Attributes)
	attrbs[constants.AttrbSource] = []string{"api"}
	attrbs[constants.AttrbOnboardingStatus] = []string{"user_created_by_api"}
	t.Run("Create with minimum properties", func(t *testing.T) {
		kcUserRep := kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrbs,
		}

		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, kcUserRep, "generateNameID", "false").Return(locationURL, nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		userRep := api.UserRepresentation{
			Username: &username,
		}

		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, false, false)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Create with all properties allowed by Bridge API", func(t *testing.T) {
		email := "toto@elca.ch"
		enabled := true
		emailVerified := true
		firstName := "Titi"
		lastName := "Tutu"
		phoneNumber := "+41789456"
		phoneNumberVerified := true
		label := "Label"
		gender := "M"
		birthDate := "01/01/1988"
		locale := "de"

		groups := []string{"145-784-545251"}
		trustIDGroups := []string{"l1_support_agent"}
		roles := []string{"445-4545-751515"}

		birthLocation := "Rolle"
		nationality := "CH"
		idDocumentType := "Card ID"
		idDocumentNumber := "1234-4567-VD-3"
		idDocumentExpiration := "23.12.2019"
		idDocumentCountry := "IT"

		onboardingStatus := "user_created_by_api"

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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		userRep := api.UserRepresentation{
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
		kcUserRep := kc.UserRepresentation{
			Attributes: &attrbs,
		}

		mocks.keycloakClient.EXPECT().CreateUser(accessToken, realmName, targetRealmName, kcUserRep, "generateNameID", "false").Return("", fmt.Errorf("Invalid input"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		userRep := api.UserRepresentation{}
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		location, err := managementComponent.CreateUser(ctx, targetRealmName, userRep, false, false, false)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	})
}

func TestCreateUserInSocialRealm(t *testing.T) {
	// Only test branches not reached by TestCreateUserInSocialRealm
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	username := "test"
	realmName := "my-realm"
	email := "user@domain.com"
	anyError := errors.New("any error")
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	userRep := api.UserRepresentation{
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
		err := managementComponent.onAlreadyExistsUser("", 0, ptr(""))
		assert.IsType(t, errorhandler.Error{}, err)
		errWithDetails := err.(errorhandler.Error)
		assert.Equal(t, http.StatusConflict, errWithDetails.Status)
	})
}

func TestCheckGLN(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	realmName := "my-realm"
	gln := "123456789"
	firstName := "first"
	lastName := "last"
	kcUser := kc.UserRepresentation{FirstName: &firstName, LastName: &lastName}
	anyError := errors.New("any error")
	ctx := context.WithValue(context.TODO(), cs.CtContextRealm, realmName)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetRealmAdminConfiguration fails", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{}, anyError)

		err := managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("BusinessID not used as a GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)
		bTrue := true
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{BusinessIDIsNotGLN: &bTrue}, nil)

		err := managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)

		assert.Nil(t, err)
		assert.NotNil(t, kcUser.GetAttributeString(constants.AttrbBusinessID))
		assert.Equal(t, gln, *kcUser.GetAttributeString(constants.AttrbBusinessID))
	})
	t.Run("GLN feature not activated", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{}, nil)

		err := managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.Nil(t, err)
		assert.Nil(t, kcUser.GetAttributeString(constants.AttrbBusinessID))
	})

	bTrue := true
	confWithGLN := configuration.RealmAdminConfiguration{ShowGlnEditing: &bTrue}
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(confWithGLN, nil).AnyTimes()

	t.Run("Removing GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		err := managementComponent.checkGLN(ctx, realmName, true, nil, &kcUser)
		assert.Nil(t, err)
		assert.Nil(t, kcUser.GetAttributeString(constants.AttrbBusinessID))
	})
	t.Run("Using invalid GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.glnVerifier.EXPECT().ValidateGLN(firstName, lastName, gln).Return(anyError)

		err := managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("Using valid GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.glnVerifier.EXPECT().ValidateGLN(firstName, lastName, gln).Return(nil)

		err := managementComponent.checkGLN(ctx, realmName, true, &gln, &kcUser)
		assert.Nil(t, err)
	})
	t.Run("No change asked for GLN field", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		err := managementComponent.checkGLN(ctx, realmName, false, nil, &kcUser)
		assert.Nil(t, err)
	})
}

func TestDeleteUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	realmName := "master"
	username := "username"

	t.Run("Delete user with success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		err := managementComponent.DeleteUser(ctx, "master", userID)

		assert.Nil(t, err)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(fmt.Errorf("Invalid input"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		err := managementComponent.DeleteUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestGetUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	id := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	username := "username"

	t.Run("Get user with succces", func(t *testing.T) {
		email := "toto@elca.ch"
		enabled := true
		emailVerified := true
		firstName := "Titi"
		lastName := "Tutu"
		phoneNumber := "+41789456"
		phoneNumberVerified := true
		label := "Label"
		gender := "M"
		birthDate := "01/01/1988"
		nationality := "AU"
		now := time.Now().UTC()
		createdTimestamp := now.Unix()
		locale := "it"
		trustIDGroups := []string{"grp1", "grp2"}
		birthLocation := "Rolle"
		idDocumentType := "Card ID"
		idDocumentNumber := "1234-4567-VD-3"
		idDocumentExpiration := "23.12.2019"
		idDocumentCountry := "MX"
		onboardingStatus := "user_created_by_api"

		attributes := make(kc.Attributes)
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

		kcUserRep := kc.UserRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		email := "toto@elca.ch"
		enabled := true
		emailVerified := true
		firstName := "Titi"
		lastName := "Tutu"
		phoneNumber := "+41789456"
		phoneNumberVerified := true
		label := "Label"
		gender := "M"
		birthDate := "01/01/1988"
		now := time.Now().UTC()
		createdTimestamp := now.Unix()
		locale := "it"
		trustIDGroups := []string{"grp1", "grp2"}

		attributes := make(kc.Attributes)
		attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
		attributes.SetString(constants.AttrbLabel, label)
		attributes.SetString(constants.AttrbGender, gender)
		attributes.SetString(constants.AttrbBirthDate, birthDate)
		attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
		attributes.SetString(constants.AttrbLocale, locale)
		attributes.Set(constants.AttrbTrustIDGroups, trustIDGroups)

		kcUserRep := kc.UserRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		kcUserRep := kc.UserRepresentation{
			ID:       &id,
			Username: &username,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realmName, id).Return([]accreditationsclient.CheckRepresentation{}, fmt.Errorf("SQL Error"))
		mocks.logger.EXPECT().Warn(ctx, "msg", "Can't get pending checks", "err", "SQL Error")

		_, err := managementComponent.GetUser(ctx, "master", id)

		assert.NotNil(t, err)
	})

	t.Run("Error with KC", func(t *testing.T) {
		id := "1234-79894-7594"
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")

		_, err := managementComponent.GetUser(ctx, "master", id)

		assert.NotNil(t, err)
	})
}

func createUpdateUser() api.UpdatableUserRepresentation {
	username := "username"
	email := "toto@elca.ch"
	emailVerified := true
	firstName := "Titi"
	lastName := "Tutu"
	phoneNumber := "+41789456"
	phoneNumberVerified := true
	label := "Label"
	gender := "M"
	birthDate := "01/01/1988"
	locale := "de"

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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

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

	attributes := make(kc.Attributes)
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

	kcUserRep := kc.UserRepresentation{
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

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUserID, id)
	ctx = context.WithValue(ctx, cs.CtContextUsername, *userRep.Username)

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Accreditations evaluation fails", func(t *testing.T) {
		newUsername := "new-username"
		userWithNewUsername := createUpdateUser()
		userWithNewUsername.Username = &newUsername

		mocks.keycloakClient.EXPECT().GetUser(accessToken, socialRealmName, id).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, anyError)
		mocks.logger.EXPECT().Warn(ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, socialRealmName, id, userWithNewUsername)

		assert.Equal(t, anyError, err)
	})

	t.Run("Update user in realm with self register enabled", func(t *testing.T) {
		newUsername := "new-username"
		userWithNewUsername := createUpdateUser()
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
		userAPI := createUpdateUser()
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

		userRepLocked := createUpdateUser()
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

		userRepLocked := createUpdateUser()
		userRepLocked.Enabled = &enabled

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.UpdateUser(ctx, "master", id, userRepLocked)

		assert.Nil(t, err)
	})

	t.Run("Update by changing the email address", func(t *testing.T) {
		oldEmail := "toti@elca.ch"
		oldkcUserRep := kc.UserRepresentation{
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
		oldEmail := "toti@elca.ch"
		oldkcUserRep := kc.UserRepresentation{
			ID:            &id,
			Email:         &oldEmail,
			EmailVerified: userRep.EmailVerified,
		}
		withoutEmailUser := createUpdateUser()
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
		oldNumber := "+41789467"
		oldAttributes := make(kc.Attributes)
		oldAttributes.SetString(constants.AttrbPhoneNumber, oldNumber)
		oldAttributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
		oldkcUserRep2 := kc.UserRepresentation{
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
		oldNumber := "+41789467"
		oldAttributes := make(kc.Attributes)
		oldAttributes.SetString(constants.AttrbPhoneNumber, oldNumber)
		oldAttributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
		oldkcUserRep2 := kc.UserRepresentation{
			ID:         &id,
			Attributes: &oldAttributes,
		}
		withoutPhoneNumberUser := userRep
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
		userRepWithoutAttr := api.UpdatableUserRepresentation{
			Username:  userRep.Username,
			Email:     userRep.Email,
			FirstName: userRep.FirstName,
			LastName:  userRep.LastName,
		}

		oldNumber := "+41789467"
		oldAttributes := make(kc.Attributes)
		oldAttributes.SetString(constants.AttrbPhoneNumber, oldNumber)
		oldAttributes.SetBool(constants.AttrbPhoneNumberVerified, *userRep.PhoneNumberVerified)
		oldkcUserRep2 := kc.UserRepresentation{
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
		id := "1234-79894-7594"
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")
		err := managementComponent.UpdateUser(ctx, "master", id, api.UpdatableUserRepresentation{})

		assert.NotNil(t, err)
	})

	t.Run("Error - update user KC", func(t *testing.T) {
		id := "1234-79894-7594"
		kcUserRep := kc.UserRepresentation{
			ID: &id,
		}
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "myrealm"
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	anyError := errors.New("any")
	bTrue := true
	bFalse := false
	ctx := context.TODO()
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetUser fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, anyError)
		err := managementComponent.LockUser(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Can't lock disabled user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bFalse}, nil)
		err := managementComponent.LockUser(ctx, realmName, userID)
		assert.Nil(t, err)
	})
	t.Run("UpdateUser fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bFalse}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(anyError)
		err := managementComponent.UnlockUser(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Lock success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bTrue}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		err := managementComponent.LockUser(ctx, realmName, userID)
		assert.Nil(t, err)
	})
	t.Run("Unlock success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Enabled: &bFalse}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		err := managementComponent.UnlockUser(ctx, realmName, userID)
		assert.Nil(t, err)
	})
}

func TestGetUsers(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	targetRealmName := "DEP"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get user with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		username := "username"
		email := "toto@elca.ch"
		enabled := true
		emailVerified := true
		firstName := "Titi"
		lastName := "Tutu"
		phoneNumber := "+41789456"
		phoneNumberVerified := true
		label := "Label"
		gender := "M"
		birthDate := "01/01/1988"
		createdTimestamp := time.Now().UTC().Unix()

		attributes := make(kc.Attributes)
		attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
		attributes.SetString(constants.AttrbLabel, label)
		attributes.SetString(constants.AttrbGender, gender)
		attributes.SetString(constants.AttrbBirthDate, birthDate)
		attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)

		count := 10
		kcUserRep := kc.UserRepresentation{
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
		kcUsersRep := kc.UsersPageRepresentation{
			Count: &count,
			Users: []kc.UserRepresentation{kcUserRep},
		}

		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmName, targetRealmName, "groupId", "123-456-789").Return(kcUsersRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextUserID, id)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		apiUsersRep, err := managementComponent.GetUsers(ctx, "DEP", []string{"123-456-789"})

		apiUserRep := apiUsersRep.Users[0]
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		_, err := managementComponent.GetUsers(ctx, "DEP", []string{"123-456-789"})

		assert.NotNil(t, err)
	})
}

func TestGetUserChecks(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "aRealm"
	userID := "789-789-456"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetChecks returns an error", func(t *testing.T) {
		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realmName, userID).Return(nil, errors.New("db error"))
		_, err := managementComponent.GetUserChecks(ctx, realmName, userID)
		assert.NotNil(t, err)
	})
	t.Run("GetChecks returns a check", func(t *testing.T) {
		operator := "The Operator"
		dbCheck := accreditationsclient.CheckRepresentation{
			Operator: &operator,
		}
		dbChecks := []accreditationsclient.CheckRepresentation{dbCheck, dbCheck}
		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realmName, userID).Return(dbChecks, nil)
		res, err := managementComponent.GetUserChecks(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Len(t, res, len(dbChecks))
		assert.Equal(t, operator, *res[0].Operator)
	})
}

func TestGetUserAccountStatus(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmReq := "master"
	realmName := "aRealm"
	userID := "789-789-456"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("GetUser returns an error", func(t *testing.T) {
		var userRep kc.UserRepresentation
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(userRep, fmt.Errorf("Unexpected error"))
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		_, err := managementComponent.GetUserAccountStatus(ctx, realmName, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUser returns a non-enabled user", func(t *testing.T) {
		var userRep kc.UserRepresentation
		enabled := false
		userRep.Enabled = &enabled
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(userRep, nil)
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)
		status, err := managementComponent.GetUserAccountStatus(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.True(t, status["enabled"])
	})
}

func TestGetUserAccountStatusByEmail(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmReq := "master"
	realmName := "aRealm"
	userID := "1234-abcd-5678"
	email := "user@domain.ch"
	anyError := errors.New("any error")
	searchedUser := kc.UserRepresentation{
		ID:      &userID,
		Email:   &email,
		Enabled: ptrBool(true),
		Attributes: &kc.Attributes{
			constants.AttrbPhoneNumberVerified: []string{"true"},
			constants.AttrbOnboardingCompleted: []string{"true"},
		},
	}
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		users := []kc.UserRepresentation{{}, {}, {}}
		count := len(users)
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
		user1 := kc.UserRepresentation{Email: &email}
		users := []kc.UserRepresentation{user1, user1, user1}
		count := len(users)
		mocks.keycloakClient.EXPECT().GetUsers(accessToken, realmReq, realmName, "email", "="+email).Return(kc.UsersPageRepresentation{
			Count: &count,
			Users: users,
		}, nil)

		_, err := managementComponent.GetUserAccountStatusByEmail(ctx, realmName, email)

		assert.NotNil(t, err)
	})

	users := []kc.UserRepresentation{searchedUser}
	count := len(users)
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
		anyCredential := kc.CredentialRepresentation{}
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"
	clientID := "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get role with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		composite := false
		containerID := "containerId"
		description := "description role"
		clientRole := true
		name := "client name"

		kcRoleRep := kc.RoleRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetClientRolesForUser(ctx, "master", userID, clientID)

		apiRoleRep := apiRolesRep[0]
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClientRolesForUser(ctx, "master", userID, clientID)

		assert.NotNil(t, err)
	})
}

func TestAddClientRolesToUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"
	clientID := "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Add role with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		composite := false
		containerID := "containerId"
		description := "description role"
		clientRole := true
		name := "client name"

		mocks.keycloakClient.EXPECT().AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, userID, clientID string, roles []kc.RoleRepresentation) error {
				role := roles[0]
				assert.Equal(t, id, *role.ID)
				assert.Equal(t, name, *role.Name)
				assert.Equal(t, clientRole, *role.ClientRole)
				assert.Equal(t, composite, *role.Composite)
				assert.Equal(t, containerID, *role.ContainerID)
				assert.Equal(t, description, *role.Description)
				return nil
			})

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		roleRep := api.RoleRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.AddClientRolesToUser(ctx, "master", userID, clientID, []api.RoleRepresentation{})

		assert.NotNil(t, err)
	})
}

func TestDeleteClientRolesFromUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"
	clientID := "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Delete role with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		name := "client name"

		mocks.keycloakClient.EXPECT().DeleteClientRolesFromUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		err := managementComponent.DeleteClientRolesFromUser(ctx, realmName, userID, clientID, id, name)

		assert.Nil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteClientRolesFromUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).Return(fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.DeleteClientRolesFromUser(ctx, "master", userID, clientID, "", "")

		assert.NotNil(t, err)
	})
}

func TestGetRolesOfUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get role with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		composite := false
		containerID := "containerId"
		description := "description role"
		clientRole := false
		name := "client name"

		kcRoleRep := kc.RoleRepresentation{
			ID:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerID: &containerID,
			Description: &description,
		}

		kcRoleRepWithAttributes := kc.RoleRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		apiRoleRep := apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.ID)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerID)
		assert.Equal(t, description, *apiRoleRep.Description)
	})
	t.Run("GetNonBusinessRole", func(t *testing.T) {
		id := "1234-7454-4516"
		kcRoleRep := kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return([]kc.RoleRepresentation{kcRoleRep}, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, *kcRoleRep.ID).Return(kcRoleRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		res, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, []api.RoleRepresentation{}, res)
	})

	t.Run("Error GetRole", func(t *testing.T) {
		id := "1234-7454-4516"
		kcRoleRep := kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return([]kc.RoleRepresentation{kcRoleRep}, nil)
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, *kcRoleRep.ID).Return(kcRoleRep, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRolesOfUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestAddRoleOfUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"
	roleID1 := "rol-rol-rol-111"
	roleID2 := "rol-rol-rol-222"
	anyError := errors.New("any error")
	knownRoles := []kc.RoleRepresentation{{ID: &roleID1, Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}}}, {ID: &roleID2}}
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"
	roleID1 := "rol-rol-rol-111"
	roleID2 := "rol-rol-rol-222"
	notOwnedRoleID := "not-a-owned-role"
	anyError := errors.New("any error")
	role1 := kc.RoleRepresentation{ID: &roleID1, Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}}}
	role2 := kc.RoleRepresentation{ID: &roleID2}
	knownRoles := []kc.RoleRepresentation{role1, role2}
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get groups with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		name := "client name"

		kcGroupRep := kc.GroupRepresentation{
			ID:   &id,
			Name: &name,
		}

		var kcGroupsRep []kc.GroupRepresentation
		kcGroupsRep = append(kcGroupsRep, kcGroupRep)

		mocks.keycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return(kcGroupsRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiGroupsRep, err := managementComponent.GetGroupsOfUser(ctx, "master", userID)

		apiGroupRep := apiGroupsRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiGroupRep.ID)
		assert.Equal(t, name, *apiGroupRep.Name)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return([]kc.GroupRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetGroupsOfUser(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestSetGroupsToUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "a-valid-access-token"
	realmName := "my-realm"
	userID := "USER-IDEN-IFIE-R123"
	groupID := "user-group-1"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	t.Run("AddGroupToUser: KC fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().AddGroupToUser(accessToken, realmName, userID, groupID).Return(errors.New("kc error"))
		err := managementComponent.AddGroupToUser(ctx, realmName, userID, groupID)
		assert.NotNil(t, err)
	})
	t.Run("DeleteGroupForUser: KC fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroupFromUser(accessToken, realmName, userID, groupID).Return(errors.New("kc error"))
		err := managementComponent.DeleteGroupForUser(ctx, realmName, userID, groupID)
		assert.NotNil(t, err)
	})
	t.Run("AddGroupToUser: Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().AddGroupToUser(accessToken, realmName, userID, groupID).Return(nil)
		err := managementComponent.AddGroupToUser(ctx, realmName, userID, groupID)
		assert.Nil(t, err)
	})
	t.Run("DeleteGroupForUser: Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroupFromUser(accessToken, realmName, userID, groupID).Return(nil)
		err := managementComponent.DeleteGroupForUser(ctx, realmName, userID, groupID)
		assert.Nil(t, err)
	})
}

func TestGetAvailableTrustIDGroups(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	realmName := "master"

	res, err := component.GetAvailableTrustIDGroups(context.TODO(), realmName)
	assert.Nil(t, err)
	assert.Len(t, res, len(allowedTrustIDGroups))
}

func TestGetTrustIDGroupsOfUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	groups := []string{"some", "/groups"}
	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"
	attrbs := kc.Attributes{constants.AttrbTrustIDGroups: groups}
	ctx := context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Keycloak fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, errors.New("kc error"))
		_, err := component.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.NotNil(t, err)
	})
	t.Run("User without attributes", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, nil)
		res, err := component.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Len(t, res, 0)
	})
	t.Run("User has attributes", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Attributes: &attrbs}, nil)
		res, err := component.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Equal(t, "some", res[0])
		assert.Equal(t, "groups", res[1]) // Without heading slash
	})
}

func TestSetTrustIDGroupsToUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="

	username := "user"
	realmName := "master"
	userID := "789-1234-5678"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Set groups with success", func(t *testing.T) {
		kcUserRep := kc.UserRepresentation{
			Username: &username,
		}
		grpNames := []string{"grp1", "grp2"}
		extGrpNames := []string{"/grp1", "/grp2"}
		attrs := make(kc.Attributes)
		attrs.Set(constants.AttrbTrustIDGroups, extGrpNames)
		kcUserRep2 := kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrs,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, kcUserRep2).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.Nil(t, err)
	})

	t.Run("Try to set unknown group", func(t *testing.T) {
		grpNames := []string{"grp1", "grp3"}
		attrs := make(map[string][]string)
		attrs["trustIDGroups"] = grpNames

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.NotNil(t, err)
	})

	t.Run("Error while get user", func(t *testing.T) {
		grpNames := []string{"grp1", "grp2"}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.NotNil(t, err)
	})

	t.Run("Error while update user", func(t *testing.T) {
		kcUserRep := kc.UserRepresentation{
			Username: &username,
		}
		grpNames := []string{"grp1", "grp2"}
		extGrpNames := []string{"/grp1", "/grp2"}
		attrs := make(kc.Attributes)
		attrs.Set(constants.AttrbTrustIDGroups, extGrpNames)
		kcUserRep2 := kc.UserRepresentation{
			Username:   &username,
			Attributes: &attrs,
		}
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, kcUserRep2).Return(fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)

		assert.NotNil(t, err)
	})
}

func TestResetPassword(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	password := "P@ssw0rd"
	typePassword := "password"
	username := "username"

	t.Run("Change password", func(t *testing.T) {
		kcCredRep := kc.CredentialRepresentation{
			Type:  &typePassword,
			Value: &password,
		}

		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, kcCredRep).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		passwordRep := api.PasswordRepresentation{
			Value: &password,
		}

		_, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
	})
	t.Run("No password offered", func(t *testing.T) {
		id := "master_id"
		keycloakVersion := "4.8.3"
		realm := "master"
		displayName := "Master"
		enabled := true

		policy := "forceExpiredPasswordChange(365) and specialChars(1) and upperCase(1) and lowerCase(1) and length(4) and digits(1) and notUsername(undefined)"
		kcRealmRep := kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
			PasswordPolicy:  &policy,
		}

		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kcRealmRep, nil).AnyTimes()

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		passwordRep := api.PasswordRepresentation{
			Value: nil,
		}

		pwd, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
		assert.NotNil(t, pwd)
	})
	t.Run("No password offered, no keycloak policy", func(t *testing.T) {
		id := "master_id"

		kcRealmRep := kc.RealmRepresentation{
			ID: &id,
		}

		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kcRealmRep, nil).AnyTimes()

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		passwordRep := api.PasswordRepresentation{
			Value: nil,
		}

		pwd, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
		assert.NotNil(t, pwd)
	})
	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, gomock.Any()).Return(fmt.Errorf("Invalid input"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		passwordRep := api.PasswordRepresentation{
			Value: &password,
		}
		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Invalid input")
		_, err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.NotNil(t, err)
	})
}

func TestRecoveryCode(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	username := "username"
	code := "123456"

	t.Run("RecoveryCode", func(t *testing.T) {
		kcCodeRep := kc.RecoveryCodeRepresentation{
			Code: &code,
		}

		mocks.keycloakClient.EXPECT().CreateRecoveryCode(accessToken, realmName, userID).Return(kcCodeRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		recoveryCode, err := managementComponent.CreateRecoveryCode(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, code, recoveryCode)
	})

	t.Run("RecoveryCode already exists", func(t *testing.T) {
		err409 := kc.HTTPError{
			HTTPStatus: 409,
			Message:    "Conflict",
		}
		kcCodeRep := kc.RecoveryCodeRepresentation{}

		mocks.keycloakClient.EXPECT().CreateRecoveryCode(accessToken, realmName, userID).Return(kcCodeRep, err409)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "409:Conflict")
		_, err := managementComponent.CreateRecoveryCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		kcCodeRep := kc.RecoveryCodeRepresentation{}
		mocks.keycloakClient.EXPECT().CreateRecoveryCode(accessToken, realmName, userID).Return(kcCodeRep, fmt.Errorf("Error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Error")
		_, err := managementComponent.CreateRecoveryCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestActivationCode(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	username := "username"
	code := "123456"

	t.Run("ActivationCode", func(t *testing.T) {
		kcCodeRep := kc.ActivationCodeRepresentation{
			Code: &code,
		}

		mocks.keycloakClient.EXPECT().CreateActivationCode(accessToken, realmName, userID).Return(kcCodeRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		activationCode, err := managementComponent.CreateActivationCode(ctx, "master", userID)

		assert.Nil(t, err)
		assert.Equal(t, code, activationCode)
	})

	t.Run("Error", func(t *testing.T) {
		kcCodeRep := kc.ActivationCodeRepresentation{}
		mocks.keycloakClient.EXPECT().CreateActivationCode(accessToken, realmName, userID).Return(kcCodeRep, fmt.Errorf("Error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Error")
		_, err := managementComponent.CreateActivationCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestExecuteActionsEmail(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "1245-7854-8963"
	reqActions := []api.RequiredAction{initPasswordAction, "action1", "action2"}
	actions := []string{initPasswordAction, "action1", "action2"}
	key1 := "key1"
	value1 := "value1"
	key2 := "key2"
	value2 := "value2"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Send email actions", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions, key1, value1, key2, value2).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions, key1, value1, key2, value2)

		assert.Nil(t, err)
	})
	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions).Return(fmt.Errorf("Invalid input"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions)

		assert.NotNil(t, err)
	})
	t.Run("Send email actions, but not sms-password-set", func(t *testing.T) {
		actions2 := []string{"action1", "action2"}
		reqActions2 := []api.RequiredAction{"action1", "action2"}
		mocks.keycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions2, key1, value1, key2, value2).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.ExecuteActionsEmail(ctx, "master", userID, reqActions2, key1, value1, key2, value2)

		assert.Nil(t, err)
	})
}

func TestRevokeAccreditations(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	accessToken := "my-access-token"
	realmName := "my-realm"
	userID := "my-user-id"
	username := "pseudo613"
	kcUser := kc.UserRepresentation{
		ID:       &userID,
		Username: &username,
	}
	anyError := errors.New("any error")
	ctx := context.TODO()
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Can't get keycloak user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, anyError)
		err := component.RevokeAccreditations(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("User has no accreditation", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		err := component.RevokeAccreditations(ctx, realmName, userID)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, http.StatusNotFound, err.(errorhandler.Error).Status)
	})
	t.Run("User has no active accreditation", func(t *testing.T) {
		attrbs := kc.Attributes{
			constants.AttrbAccreditations: []string{`{"type":"DEP","expiryDate":"31.12.2059","creationMillis":1643700000000,"revoked":true}`},
		}
		kcUser.Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		err := component.RevokeAccreditations(ctx, realmName, userID)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, http.StatusNotFound, err.(errorhandler.Error).Status)
	})
	t.Run("Fails to update keycloak user", func(t *testing.T) {
		attrbs := kc.Attributes{
			constants.AttrbAccreditations: []string{`{"type":"DEP","expiryDate":"31.12.2059","creationMillis":1643700000000}`},
		}
		kcUser.Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(anyError)
		err := component.RevokeAccreditations(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Success", func(t *testing.T) {
		attrbs := kc.Attributes{
			constants.AttrbAccreditations: []string{`{"type":"DEP","expiryDate":"31.12.2059","creationMillis":1643700000000}`},
		}
		kcUser.Attributes = &attrbs
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		err := component.RevokeAccreditations(ctx, realmName, userID)
		assert.Nil(t, err)
	})
}

func TestSendSmsCode(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	username := "userName"
	userID := "1245-7854-8963"

	t.Run("Send new sms code", func(t *testing.T) {
		code := "1234"
		mocks.keycloakClient.EXPECT().SendSmsCode(accessToken, realmName, userID).Return(kc.SmsCodeRepresentation{Code: &code}, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(gomock.Any(), "err", "Invalid input")
		_, err := managementComponent.SendSmsCode(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestSendOnboardingEmail(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	onboardingRedirectURI := "http://successURL"
	onboardingClientID := "onboardingid"
	accessToken := "TOKEN=="
	realmName := "master"
	customerRealmName := "customer"
	userID := "1245-7854-8963"
	username := "username"
	ctx := context.Background()
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, customerRealmName)
	anyError := errors.New("unexpected error")

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
		attributes := make(kc.Attributes)
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
		attributes := make(kc.Attributes)
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
		computedOnboardingRedirectURI := onboardingRedirectURI + "?customerRealm=" + customerRealmName
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "1245-7854-8963"

	key1 := "key1"
	value1 := "value1"
	key2 := "key2"
	value2 := "value2"
	key3 := "key3"
	value3 := "value3"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Send email", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendReminderEmail(accessToken, realmName, userID, key1, value1, key2, value2, key3, value3).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SendReminderEmail(ctx, "master", userID, key1, value1, key2, value2, key3, value3)

		assert.Nil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().SendReminderEmail(accessToken, realmName, userID).Return(fmt.Errorf("Invalid input"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.SendReminderEmail(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestResetSmsCounter(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "1245-7854-8963"
	id := "1234-7454-4516"
	username := "username"
	email := "toto@elca.ch"
	enabled := true
	emailVerified := true
	firstName := "Titi"
	lastName := "Tutu"
	phoneNumber := "+41789456"
	phoneNumberVerified := true
	label := "Label"
	gender := "M"
	birthDate := "01/01/1988"
	createdTimestamp := time.Now().UTC().Unix()
	attributes := make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
	attributes.SetString(constants.AttrbLabel, label)
	attributes.SetString(constants.AttrbGender, gender)
	attributes.SetString(constants.AttrbBirthDate, birthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
	attributes.SetInt(constants.AttrbSmsSent, 5)
	attributes.SetInt(constants.AttrbSmsAttempts, 5)

	kcUserRep := kc.UserRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		err := managementComponent.ResetSmsCounter(ctx, "master", userID)

		assert.Nil(t, err)
	})

	t.Run("Error at GetUser", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, fmt.Errorf("error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		err := managementComponent.ResetSmsCounter(ctx, "master", userID)

		assert.NotNil(t, err)
	})

	t.Run("Error at UpdateUser", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUserRep, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, kcUserRep).Return(fmt.Errorf("error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		err := managementComponent.ResetSmsCounter(ctx, "master", userID)

		assert.NotNil(t, err)
	})
}

func TestGetCredentialsForUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmReq := "master"
	realmName := "otherRealm"
	userID := "1245-7854-8963"

	t.Run("Get credentials for user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return([]kc.CredentialRepresentation{}, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmReq)

		_, err := managementComponent.GetCredentialsForUser(ctx, realmName, userID)

		assert.Nil(t, err)
	})
}

func TestDeleteCredentialsForUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmReq := "master"
	realmName := "master"
	userID := "1245-7854-8963"
	credMfa1 := kc.CredentialRepresentation{ID: ptr("cred-mfa-1"), Type: ptr("any-mfa")}
	credMfa2 := kc.CredentialRepresentation{ID: ptr("cred-mfa-2"), Type: ptr("any-mfa")}
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "1245-7854-8963"
	credentialID := "987-654-321"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Detect credential type-Keycloak call fails", func(t *testing.T) {
		kcErr := errors.New("keycloak error")
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return(nil, kcErr)

		err := managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.Equal(t, kcErr, err)
	})

	t.Run("Detect credential type-Credential not found", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return(nil, nil)

		err := managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.NotNil(t, err)
	})

	foundCredType := "ctpapercard"
	credentials := []kc.CredentialRepresentation{{ID: &credentialID, Type: &foundCredType}}
	mocks.keycloakClient.EXPECT().GetCredentials(accessToken, realmName, userID).Return(credentials, nil).AnyTimes()

	t.Run("Detect credential type-Credential found", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ResetPapercardFailures(accessToken, realmName, userID, credentialID).Return(nil)

		err := managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.Nil(t, err)
	})

	t.Run("Can't unlock paper card", func(t *testing.T) {
		unlockErr := errors.New("unlock error")
		mocks.keycloakClient.EXPECT().ResetPapercardFailures(accessToken, realmName, userID, credentialID).Return(unlockErr)

		err := managementComponent.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.Equal(t, unlockErr, err)
	})
}

func TestClearUserLoginFailures(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	accessToken := "TOKEN=="
	realm := "master"
	userID := "1245-7854-8963"
	ctx := context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Error occured", func(t *testing.T) {
		expectedError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().ClearUserLoginFailures(accessToken, realm, userID).Return(expectedError)
		err := component.ClearUserLoginFailures(ctx, realm, userID)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().ClearUserLoginFailures(accessToken, realm, userID).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		err := component.ClearUserLoginFailures(ctx, realm, userID)
		assert.Nil(t, err)
	})
}

func TestGetAttackDetectionStatus(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	accessToken := "TOKEN=="
	realm := "master"
	userID := "1245-7854-8963"
	ctx := context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)
	kcResult := map[string]interface{}{}

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Error occured", func(t *testing.T) {
		expectedError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetAttackDetectionStatus(accessToken, realm, userID).Return(kcResult, expectedError)
		_, err := component.GetAttackDetectionStatus(ctx, realm, userID)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		var expectedFailures int64 = 57
		kcResult["numFailures"] = expectedFailures
		mocks.keycloakClient.EXPECT().GetAttackDetectionStatus(accessToken, realm, userID).Return(kcResult, nil)
		res, err := component.GetAttackDetectionStatus(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Equal(t, expectedFailures, *res.NumFailures)
	})
}

func TestGetRoles(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get roles with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		composite := false
		containerID := "containerId"
		description := "description role"
		clientRole := false
		name := "name"

		kcRoleRep := kc.RoleRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetRoles(ctx, "master")

		apiRoleRep := apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.ID)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerID)
		assert.Equal(t, description, *apiRoleRep.Description)
	})

	t.Run("NonBusinessRole are not returned", func(t *testing.T) {
		id := "1234-7454-4516"
		kcRoleRep := kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return([]kc.RoleRepresentation{kcRoleRep}, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetRoles(ctx, "master")

		assert.Nil(t, err)
		assert.Equal(t, []api.RoleRepresentation{}, apiRolesRep)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRolesWithAttributes(accessToken, realmName).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRoles(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestGetRole(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get roles with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		composite := false
		containerID := "containerId"
		description := "description role"
		clientRole := false
		name := "name"

		kcRoleRep := kc.RoleRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

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
		id := "1234-7454-4516"
		kcRoleRep := kc.RoleRepresentation{ID: &id}
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, id).Return(kcRoleRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRole(ctx, "master", id)

		assert.NotNil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		id := "1234-7454-4516"
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, id).Return(kc.RoleRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRole(ctx, "master", id)

		assert.NotNil(t, err)
	})
}

func TestCreateRole(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	username := "username"
	userID := "testUserID"
	name := "test"
	realmName := "master"
	roleID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	locationURL := "http://toto.com/realms/" + roleID

	t.Run("Create", func(t *testing.T) {
		kcRoleRep := kc.RoleRepresentation{
			Name:       &name,
			Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}},
		}

		mocks.keycloakClient.EXPECT().CreateRole(accessToken, realmName, kcRoleRep).Return(locationURL, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		roleRep := api.RoleRepresentation{
			Name: &name,
		}

		location, err := managementComponent.CreateRole(ctx, realmName, roleRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		kcRoleRep := kc.RoleRepresentation{
			Attributes: &map[string][]string{"BUSINESS_ROLE_FLAG": {"true"}},
		}

		mocks.keycloakClient.EXPECT().CreateRole(accessToken, realmName, kcRoleRep).Return("", fmt.Errorf("Invalid input"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		roleRep := api.RoleRepresentation{}
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		location, err := managementComponent.CreateRole(ctx, realmName, roleRep)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	})
}

func TestUpdateRole(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	accessToken := "TOKEN=="
	roleID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	roleName := "roleName"
	realmName := "master"
	username := "username"
	attributes := map[string][]string{
		"BUSINESS_ROLE_FLAG": {"true"},
	}

	role := kc.RoleRepresentation{
		ID:         &roleID,
		Name:       &roleName,
		Attributes: &attributes,
	}
	inputRole := api.RoleRepresentation{Name: &roleName}
	anyError := errors.New("any error")
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	roleID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	roleName := "roleName"
	realmName := "master"
	username := "username"
	userID := "testUserID"

	attributes := map[string][]string{
		"BUSINESS_ROLE_FLAG": {"true"},
	}

	role := kc.RoleRepresentation{
		ID:         &roleID,
		Name:       &roleName,
		Attributes: &attributes,
	}

	t.Run("Delete role with success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRole(accessToken, realmName, roleID).Return(role, nil)
		mocks.keycloakClient.EXPECT().DeleteRole(accessToken, realmName, roleID).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := managementComponent.DeleteRole(ctx, realmName, roleID)

		assert.Nil(t, err)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get groups with succces, non empty result", func(t *testing.T) {
		id := "1234-7454-4516"
		path := "path_group"
		name := "group1"
		realmRoles := []string{"role1"}

		kcGroupRep := kc.GroupRepresentation{
			ID:         &id,
			Name:       &name,
			Path:       &path,
			RealmRoles: &realmRoles,
		}

		var kcGroupsRep []kc.GroupRepresentation
		kcGroupsRep = append(kcGroupsRep, kcGroupRep)

		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realmName).Return(kcGroupsRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiGroupsRep, err := managementComponent.GetGroups(ctx, "master")

		apiGroupRep := apiGroupsRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiGroupRep.ID)
		assert.Equal(t, name, *apiGroupRep.Name)
	})

	t.Run("Get groups with success, empty result", func(t *testing.T) {
		var kcGroupsRep []kc.GroupRepresentation
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realmName).Return(kcGroupsRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		apiGroupsRep, err := managementComponent.GetGroups(ctx, "master")

		assert.Nil(t, err)
		assert.NotNil(t, apiGroupsRep)
		assert.Equal(t, 0, len(apiGroupsRep))
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{}, fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetGroups(ctx, "master")

		assert.NotNil(t, err)
	})
}

func TestCreateGroup(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	username := "username"
	userID := "testUserID"
	name := "test"
	realmName := "master"
	targetRealmName := "DEP"
	groupID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	locationURL := "http://toto.com/realms/" + groupID

	t.Run("Create", func(t *testing.T) {
		kcGroupRep := kc.GroupRepresentation{
			Name: &name,
		}

		mocks.keycloakClient.EXPECT().CreateGroup(accessToken, targetRealmName, kcGroupRep).Return(locationURL, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)
		ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		groupRep := api.GroupRepresentation{
			Name: &name,
		}

		location, err := managementComponent.CreateGroup(ctx, targetRealmName, groupRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		kcGroupRep := kc.GroupRepresentation{}

		mocks.keycloakClient.EXPECT().CreateGroup(accessToken, targetRealmName, kcGroupRep).Return("", fmt.Errorf("Invalid input"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		groupRep := api.GroupRepresentation{}
		mocks.logger.EXPECT().Warn(ctx, "err", "Invalid input")

		location, err := managementComponent.CreateGroup(ctx, targetRealmName, groupRep)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	})
}

func TestDeleteGroup(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	groupID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	groupName := "groupName"
	targetRealmName := "DEP"
	realmName := "master"
	username := "username"
	userID := "testUserID"

	group := kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}

	t.Run("Delete group with success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().DeleteGroup(accessToken, targetRealmName, groupID).Return(nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmName, groupID).Return(group, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.configurationDBModule.EXPECT().DeleteAllAuthorizationsWithGroup(ctx, targetRealmName, groupName).Return(fmt.Errorf("Error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")

		err := managementComponent.DeleteGroup(ctx, targetRealmName, groupID)

		assert.NotNil(t, err)
	})

	t.Run("Error from KC client", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	targetRealmname := "DEP"
	groupID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	groupName := "groupName"
	username := "username"
	action := "action"

	group := kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}

	t.Run("Get authorizations with succces", func(t *testing.T) {
		configurationAuthz := []configuration.Authorization{
			{
				RealmID:   &realmName,
				GroupName: &groupName,
				Action:    &action,
			},
		}

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.configurationDBModule.EXPECT().GetAuthorizations(ctx, targetRealmname, groupName).Return(configurationAuthz, nil)
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmname, groupID).Return(group, nil)

		apiAuthorizationRep, err := managementComponent.GetAuthorizations(ctx, targetRealmname, groupID)

		matrix := map[string]map[string]map[string]struct{}{
			"action": {},
		}

		expectedAPIAuthorization := api.AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIAuthorization, apiAuthorizationRep)
	})

	t.Run("Error when retrieving authorizations from DB", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmname, groupID).Return(group, nil)
		mocks.configurationDBModule.EXPECT().GetAuthorizations(gomock.Any(), targetRealmname, groupName).Return([]configuration.Authorization{}, fmt.Errorf("Error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")

		_, err := managementComponent.GetAuthorizations(ctx, targetRealmname, groupID)

		assert.NotNil(t, err)
	})

	t.Run("Error with KC", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		mocks.keycloakClient.EXPECT().GetGroup(accessToken, targetRealmname, groupID).Return(kc.GroupRepresentation{}, errors.New("Error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Error")
		_, err := managementComponent.GetAuthorizations(ctx, targetRealmname, groupID)
		assert.NotNil(t, err)
	})
}

func TestUpdateAuthorizations(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "customer1"
	targetRealmName := "DEP"
	groupID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	groupName := "groupName"
	username := "username"

	realm := kc.RealmRepresentation{
		ID:    &targetRealmName,
		Realm: &targetRealmName,
	}
	realms := []kc.RealmRepresentation{realm}

	group := kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	groups := []kc.GroupRepresentation{group}

	action := "MGMT_action"
	matrix := map[string]map[string]map[string]struct{}{
		action: {},
	}

	apiAuthorizations := api.AuthorizationsRepresentation{
		Matrix: &matrix,
	}

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
			mocks.eventsReporter.EXPECT().ReportEvent(ctx, gomock.Any()),
			mocks.transaction.EXPECT().Close(),
		)
		err := managementComponent.UpdateAuthorizations(ctx, targetRealmName, groupID, apiAuthorizations)
		assert.Nil(t, err)
	})

	t.Run("Authorizations provided not valid", func(t *testing.T) {
		jsonMatrix := `{
			"Action1": {},
			"Action2": {"*": {}, "realm1": {}}
		}`

		var matrix map[string]map[string]map[string]struct{}
		if err := json.Unmarshal([]byte(jsonMatrix), &matrix); err != nil {
			assert.Fail(t, "")
		}

		apiAuthorizations := api.AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	targetRealmName := "DEP"
	groupID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	groupName := "groupName"
	targetGroupName := "targetGroup"
	targetGroupID := "124352"
	action := "MGMT_DeleteUser"
	actionRealm := "MGMT_GetRealm"
	username := "username"
	userID := "TestUserID"
	star := "*"

	expectedErr := errors.New("test error")

	group := kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	groups := []kc.GroupRepresentation{
		{
			ID:   &targetGroupID,
			Name: &targetGroupName,
		},
	}

	realm := kc.RealmRepresentation{
		ID:    &targetRealmName,
		Realm: &targetRealmName,
	}
	realms := []kc.RealmRepresentation{realm}

	matrix := map[string]map[string]map[string]struct{}{
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
	matrixRealm := map[string]map[string]map[string]struct{}{
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
	parent := configuration.Authorization{
		RealmID:         &realmName,
		GroupName:       group.Name,
		Action:          &action,
		TargetRealmID:   &star,
		TargetGroupName: &star,
	}

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		global := "MGMT_GetActions"
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	targetRealmName := "DEP"
	groupID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	groupName := "groupName"
	targetGroupName := "targetGroup"
	targetGroupID := "124352"
	action := "MGMT_DeleteUser"
	globalAction := "MGMT_GetActions"
	realmAction := "MGMT_GetRealm"
	username := "username"
	star := "*"

	expectedErr := errors.New("test error")

	group := kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}

	targetGroup := kc.GroupRepresentation{
		ID:   &targetGroupID,
		Name: &targetGroupName,
	}

	extpectedAuthzNegativeMsg := api.AuthorizationMessage{
		Authorized: false,
	}
	extpectedAuthzPositiveMsg := api.AuthorizationMessage{
		Authorized: true,
	}

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	targetRealmName := "DEP"
	groupID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	groupName := "groupName"
	targetGroupName := "targetGroup"
	targetGroupID := "124352"
	action := "MGMT_DeleteUser"
	username := "username"
	userID := "testUserID"
	star := "*"

	expectedErr := errors.New("test error")

	group := kc.GroupRepresentation{
		ID:   &groupID,
		Name: &groupName,
	}
	targetGroup := kc.GroupRepresentation{
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

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
		globalAction := "MGMT_GetActions"
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	clientID := "15436-464-4"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get roles with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		composite := false
		containerID := "containerId"
		description := "description role"
		clientRole := true
		name := "name"

		kcRoleRep := kc.RoleRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		apiRolesRep, err := managementComponent.GetClientRoles(ctx, "master", clientID)

		apiRoleRep := apiRolesRep[0]
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetClientRoles(ctx, "master", clientID)

		assert.NotNil(t, err)
	})
}

func TestCreateClientRole(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	clientID := "456-789-147"

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Add role with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		composite := false
		containerID := "containerId"
		description := "description role"
		clientRole := true
		name := "client name"

		locationURL := "http://location.url"

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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		roleRep := api.RoleRepresentation{
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.CreateClientRole(ctx, "master", clientID, api.RoleRepresentation{})

		assert.NotNil(t, err)
	})
}

func TestDeleteClientRole(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "test"
	clientID := "456-789-147"
	roleID := "123-456-789"

	role := kc.RoleRepresentation{
		ID:          ptrString("1234-7454-4516"),
		Name:        ptrString("name"),
		ClientRole:  ptrBool(true),
		Composite:   ptrBool(false),
		ContainerID: ptrString("456-789-147"),
		Description: ptrString("description role"),
	}

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

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
		role := kc.RoleRepresentation{
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
		role := kc.RoleRepresentation{
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmID := "master_id"

	mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()
	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Get existing config", func(t *testing.T) {
		id := realmID
		keycloakVersion := "4.8.3"
		realm := "master"
		displayName := "Master"
		enabled := true

		kcRealmRep := kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)

		clientID := "ClientID"
		redirectURI := "http://redirect.url.com/test"

		realmConfig := configuration.RealmConfiguration{
			DefaultClientID:    &clientID,
			DefaultRedirectURI: &redirectURI,
		}

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, realmID).Return(realmConfig, nil)

		configJSON, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.Nil(t, err)
		assert.Equal(t, *configJSON.DefaultClientID, *realmConfig.DefaultClientID)
		assert.Equal(t, *configJSON.DefaultRedirectURI, *realmConfig.DefaultRedirectURI)
	})

	t.Run("Get empty config", func(t *testing.T) {
		id := realmID
		keycloakVersion := "4.8.3"
		realm := "master"
		displayName := "Master"
		enabled := true

		kcRealmRep := kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, realmID).Return(configuration.RealmConfiguration{}, errorhandler.Error{})

		configJSON, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.Nil(t, err)
		assert.Nil(t, configJSON.DefaultClientID)
		assert.Nil(t, configJSON.DefaultRedirectURI)
	})

	t.Run("Unknown realm", func(t *testing.T) {
		id := realmID
		keycloakVersion := "4.8.3"
		realm := "master"
		displayName := "Master"
		enabled := true

		kcRealmRep := kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, errors.New("error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

		_, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.NotNil(t, err)
	})

	t.Run("DB error", func(t *testing.T) {
		id := realmID
		keycloakVersion := "4.8.3"
		realm := "master"
		displayName := "Master"
		enabled := true

		kcRealmRep := kc.RealmRepresentation{
			ID:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmID).Return(kcRealmRep, nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, realmID).Return(configuration.RealmConfiguration{}, errors.New("error"))

		_, err := managementComponent.GetRealmCustomConfiguration(ctx, realmID)

		assert.NotNil(t, err)
	})
}

func TestUpdateRealmCustomConfiguration(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmID := "master_id"

	id := realmID
	keycloakVersion := "4.8.3"
	realm := "master"
	displayName := "Master"
	enabled := true

	kcRealmRep := kc.RealmRepresentation{
		ID:              &id,
		KeycloakVersion: &keycloakVersion,
		Realm:           &realm,
		DisplayName:     &displayName,
		Enabled:         &enabled,
	}

	clients := make([]kc.ClientRepresentation, 2)
	clientID1 := "clientID1"
	clientName1 := "clientName1"
	redirectURIs1 := []string{"https://www.cloudtrust.io/*", "https://www.cloudtrust-old.com/*"}
	clientID2 := "clientID2"
	clientName2 := "clientName2"
	redirectURIs2 := []string{"https://www.cloudtrust2.io/*", "https://www.cloudtrust2-old.com/*"}
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

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	clientID := "clientID1"
	redirectURI := "https://www.cloudtrust.io/test"
	configInit := api.RealmCustomConfiguration{
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

		clientID := "clientID1Nok"
		redirectURI := "https://www.cloudtrust.io/test"
		configInit := api.RealmCustomConfiguration{
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

		clientID := "clientID1"
		redirectURI := "https://www.cloudtrustnok.io/test"
		configInit := api.RealmCustomConfiguration{
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

		clientID := "clientID1"
		redirectURI := "https://wwwacloudtrust.io/test"
		configInit := api.RealmCustomConfiguration{
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	realmName := "myrealm"
	realmID := "1234-5678"
	accessToken := "acce-ssto-ken"
	expectedError := errors.New("expectedError")
	var dbAdminConfig configuration.RealmAdminConfiguration
	apiAdminConfig := api.ConvertRealmAdminConfigurationFromDBStruct(dbAdminConfig)
	ctx := context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Request to Keycloak client fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{}, expectedError)
		_, err := component.GetRealmAdminConfiguration(ctx, realmName)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Request to database fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, gomock.Any()).Return(dbAdminConfig, expectedError)
		_, err := component.GetRealmAdminConfiguration(ctx, realmName)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmID).Return(dbAdminConfig, nil)
		res, err := component.GetRealmAdminConfiguration(ctx, realmName)
		assert.Nil(t, err)
		assert.Equal(t, apiAdminConfig, res)
	})
}

func TestUpdateRealmAdminConfiguration(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	realmName := "myrealm"
	realmID := "1234-5678"
	accessToken := "acce-ssto-ken"
	expectedError := errors.New("expectedError")
	ctx := context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)
	var adminConfig api.RealmAdminConfiguration

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Request to Keycloak client fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{}, expectedError)
		err := component.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Request to database fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().StoreOrUpdateAdminConfiguration(ctx, realmID, gomock.Any()).Return(expectedError)
		err := component.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{ID: &realmID}, nil)
		mocks.configurationDBModule.EXPECT().StoreOrUpdateAdminConfiguration(ctx, realmID, gomock.Any()).Return(nil)
		err := component.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Nil(t, err)
	})
}

func createBackOfficeConfiguration(JSON string) dto.BackOfficeConfiguration {
	var conf dto.BackOfficeConfiguration
	_ = json.Unmarshal([]byte(JSON), &conf)
	return conf
}

func TestRealmBackOfficeConfiguration(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	realmID := "master_id"
	groupName := "the.group"
	config := api.BackOfficeConfiguration{}
	ctx := context.WithValue(context.TODO(), cs.CtContextGroups, []string{"grp1", "grp2"})
	largeConf := `
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
	smallConf := `
		{
			"realm2": {
				"a": [ "grp1" ],
				"c": [ "grp2" ]
			}
		}
	`

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("UpdateRealmBackOfficeConfiguration - db.GetBackOfficeConfiguration fails", func(t *testing.T) {
		expectedError := errors.New("db error")
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(nil, expectedError)
		err := component.UpdateRealmBackOfficeConfiguration(ctx, realmID, groupName, config)
		assert.Equal(t, expectedError, err)
	})

	t.Run("UpdateRealmBackOfficeConfiguration - remove items", func(t *testing.T) {
		dbConf := createBackOfficeConfiguration(largeConf)
		requestConf, _ := api.NewBackOfficeConfigurationFromJSON(smallConf)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, nil)
		mocks.configurationDBModule.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, "realm1", nil, nil).Return(nil)
		mocks.configurationDBModule.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, "realm2", gomock.Not(nil), nil).Return(nil)
		mocks.configurationDBModule.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, "realm2", gomock.Not(nil), gomock.Not(nil)).Return(nil)
		err := component.UpdateRealmBackOfficeConfiguration(ctx, realmID, groupName, requestConf)
		assert.Nil(t, err)
	})

	t.Run("UpdateRealmBackOfficeConfiguration - add items", func(t *testing.T) {
		dbConf := createBackOfficeConfiguration(smallConf)
		requestConf, _ := api.NewBackOfficeConfigurationFromJSON(largeConf)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, nil)
		mocks.configurationDBModule.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, "realm1", "a", []string{"grp1"}).Return(nil)
		mocks.configurationDBModule.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, "realm2", "b", []string{"grp2"}).Return(nil)
		mocks.configurationDBModule.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, "realm2", "c", []string{"grp1"}).Return(nil)
		err := component.UpdateRealmBackOfficeConfiguration(ctx, realmID, groupName, requestConf)
		assert.Nil(t, err)
	})

	t.Run("GetRealmBackOfficeConfiguration - error", func(t *testing.T) {
		dbConf := createBackOfficeConfiguration(smallConf)
		expectedError := errors.New("db error")
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, expectedError)
		res, err := component.GetRealmBackOfficeConfiguration(ctx, realmID, groupName)
		assert.Equal(t, expectedError, err)
		assert.Nil(t, res)
	})

	t.Run("GetRealmBackOfficeConfiguration - success", func(t *testing.T) {
		dbConf := createBackOfficeConfiguration(smallConf)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, []string{groupName}).Return(dbConf, nil)
		res, err := component.GetRealmBackOfficeConfiguration(ctx, realmID, groupName)
		assert.Nil(t, err)
		assert.Equal(t, api.BackOfficeConfiguration(dbConf), res)
	})

	t.Run("GetUserRealmBackOfficeConfiguration - db error", func(t *testing.T) {
		dbError := errors.New("db error")
		groups := ctx.Value(cs.CtContextGroups).([]string)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, groups).Return(nil, dbError)
		_, err := component.GetUserRealmBackOfficeConfiguration(ctx, realmID)
		assert.Equal(t, dbError, err)
	})

	t.Run("GetUserRealmBackOfficeConfiguration - success", func(t *testing.T) {
		dbConf := createBackOfficeConfiguration(smallConf)
		groups := ctx.Value(cs.CtContextGroups).([]string)
		mocks.configurationDBModule.EXPECT().GetBackOfficeConfiguration(ctx, realmID, groups).Return(dbConf, nil)
		res, err := component.GetUserRealmBackOfficeConfiguration(ctx, realmID)
		assert.Nil(t, err)
		assert.Equal(t, api.BackOfficeConfiguration(dbConf), res)
	})
}

func TestGetFederatedIdentities(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	username := "username"
	idpName := "idpName"
	ctx := context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	t.Run("Call to keycloak fails", func(t *testing.T) {
		anyError := errors.New("any error")
		mocks.logger.EXPECT().Warn(ctx, gomock.Any())
		mocks.keycloakClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return(nil, anyError)
		_, err := managementComponent.GetFederatedIdentities(ctx, realmName, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Success - Result is empty", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return([]kc.FederatedIdentityRepresentation{}, nil)
		res, err := managementComponent.GetFederatedIdentities(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res, 0)
	})
	t.Run("Success - Result is not empty", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return([]kc.FederatedIdentityRepresentation{
			{UserID: &userID, UserName: &username, IdentityProvider: &idpName},
		}, nil)
		res, err := managementComponent.GetFederatedIdentities(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.Len(t, res, 1)
		assert.Equal(t, userID, *res[0].UserID)
		assert.Equal(t, username, *res[0].Username)
		assert.Equal(t, idpName, *res[0].IdentityProvider)
	})
}

func TestLinkShadowUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	username := "test"
	realmName := "master"
	userID := "41dbf4a8-32a9-4000-8c17-edc854c31231"
	provider := "provider"

	// Create shadow user
	t.Run("Create shadow user successfully", func(t *testing.T) {
		fedIDKC := kc.FederatedIdentityRepresentation{UserName: &username, UserID: &userID}
		fedID := api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}

		mocks.keycloakClient.EXPECT().LinkShadowUser(accessToken, realmName, userID, provider, fedIDKC).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
		ctx = context.WithValue(ctx, cs.CtContextUsername, username)

		mocks.logger.EXPECT().Warn(ctx, gomock.Any())
		err := managementComponent.LinkShadowUser(ctx, realmName, userID, provider, fedID)

		assert.NotNil(t, err)
	})
}

func TestGetIdentityProviders(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	managementComponent := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "test"

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

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
		bytes, _ := json.Marshal(res)
		assert.Equal(t, "[]", string(bytes))
	})
	t.Run("Get identity providers error", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetIdps(accessToken, realmName).Return([]kc.IdentityProviderRepresentation{}, errors.New("error"))

		_, err := managementComponent.GetIdentityProviders(ctx, realmName)
		assert.NotNil(t, err)
	})
}
