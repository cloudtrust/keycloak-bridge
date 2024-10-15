package validation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	log "github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation/mock"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	keycloakClient *mock.KeycloakClient
	archiveDB      *mock.ArchiveDBModule
	eventsReporter *mock.AuditEventsReporterModule
	tokenProvider  *mock.TokenProvider
	accredsService *mock.AccreditationsServiceClient
	configDB       *mock.ConfigurationDBModule
}

func createComponentMocks(mockCtrl *gomock.Controller) componentMocks {
	return componentMocks{
		keycloakClient: mock.NewKeycloakClient(mockCtrl),
		archiveDB:      mock.NewArchiveDBModule(mockCtrl),
		eventsReporter: mock.NewAuditEventsReporterModule(mockCtrl),
		tokenProvider:  mock.NewTokenProvider(mockCtrl),
		accredsService: mock.NewAccreditationsServiceClient(mockCtrl),
		configDB:       mock.NewConfigurationDBModule(mockCtrl),
	}
}

func (m *componentMocks) createComponent() *component {
	return NewComponent(m.keycloakClient, m.tokenProvider, m.archiveDB, m.eventsReporter, m.accredsService, m.configDB, log.NewNopLogger()).(*component)
}

func TestGetUserComponent(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	accessToken := "abcd-1234"
	realm := "my-realm"
	userID := ""
	anyError := errors.New("an error")
	ctx := context.Background()

	mocks := createComponentMocks(mockCtrl)
	component := mocks.createComponent()

	t.Run("Fails to retrieve token for technical user", func(t *testing.T) {
		kcError := errors.New("kc error")
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", kcError)
		_, err := component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUser from Keycloak fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		kcError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		_, err := component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetAdminConfiguration fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, anyError)
		_, err := component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("Missing GLN", func(t *testing.T) {
		bTrue := true
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{ShowGlnEditing: &bTrue}, nil)
		_, err := component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, nil).AnyTimes()

	t.Run("Happy path", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		_, err := component.GetUser(ctx, realm, userID)
		assert.Nil(t, err)
	})
}

func TestUpdateUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	targetRealm := "cloudtrust"
	userID := "abc789def"
	username := "pseudo88"
	accessToken := "abcdef"
	txnID := "transaction-id"
	ctx := context.TODO()
	ctx = context.WithValue(ctx, cs.CtContextRealm, targetRealm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	mocks := createComponentMocks(mockCtrl)
	component := mocks.createComponent()

	t.Run("Fails to retrieve token for technical user", func(t *testing.T) {
		user := api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		kcError := errors.New("kc error")
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", kcError)
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("No update needed", func(t *testing.T) {
		user := api.UserRepresentation{}
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.Nil(t, err)
	})

	t.Run("Fails to get user from KC", func(t *testing.T) {
		user := api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		kcError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, kcError)
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.NotNil(t, err)
	})

	t.Run("Fails to update user in KC", func(t *testing.T) {
		date := time.Now()
		user := api.UserRepresentation{
			BirthDate: &date,
		}
		kcError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.NotNil(t, err)
	})

	t.Run("Fails to update user in KC", func(t *testing.T) {
		user := api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		kcError := errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.NotNil(t, err)
	})
	mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil).AnyTimes()

	t.Run("Failed to nofifyUpdate", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{
			Attributes: &kc.Attributes{
				"accreditations": []string{`{"type":"ONE","expiryDate":"01.01.2040"}`},
			},
		}, nil)
		mocks.accredsService.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return([]string{}, errors.New("error"))

		user := api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.NotNil(t, err)
	})

	t.Run("Successful update", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)

		user := api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.Nil(t, err)
	})

	t.Run("Successful update - Current accreds not nil", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{
			Username: &username,
			Attributes: &kc.Attributes{
				"accreditations": []string{`{"type":"ONE","expiryDate":"01.01.2040"}`},
			},
		}, nil)
		mocks.accredsService.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return([]string{"ONE"}, nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any()).Times(2)
		mocks.archiveDB.EXPECT().StoreUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)

		user := api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		err := component.UpdateUser(ctx, targetRealm, userID, user, &txnID)
		assert.Nil(t, err)
	})

	t.Run("Successful update, txnid nil", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		mocks.archiveDB.EXPECT().StoreUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		user := api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		err := component.UpdateUser(ctx, targetRealm, userID, user, nil)
		assert.Nil(t, err)
	})
}

func TestUpdateUserAccreditations(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createComponentMocks(mockCtrl)
	component := mocks.createComponent()
	expectedError := errors.New("Test error")

	ctx := context.Background()
	accessToken := "TOKEN=="
	realmName := "testRealm"
	userID := "testUserID"
	username := "pseudo129"
	userAccreds := []api.AccreditationRepresentation{
		{
			Name:     ptr("ONE"),
			Validity: ptr("4y"),
		},
	}
	user := kc.UserRepresentation{Username: &username}

	t.Run("Get access token - failed ", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, expectedError)

		err := component.UpdateUserAccreditations(ctx, realmName, userID, userAccreds)
		assert.NotNil(t, err)
	})

	t.Run("Get User failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(user, expectedError)

		err := component.UpdateUserAccreditations(ctx, realmName, userID, userAccreds)
		assert.NotNil(t, err)
	})

	t.Run("Update User failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(user, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(expectedError)

		err := component.UpdateUserAccreditations(ctx, realmName, userID, userAccreds)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(user, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		err := component.UpdateUserAccreditations(ctx, realmName, userID, userAccreds)
		assert.Nil(t, err)
	})
}

func TestValidationContext(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createComponentMocks(mockCtrl)
	component := mocks.createComponent()

	validationCtx := &validationContext{
		ctx:       context.TODO(),
		realmName: "my-realm",
		userID:    "abcd-4567",
		kcUser:    &kc.UserRepresentation{},
	}
	accessToken := "abcd1234.efgh.5678ijkl"
	anyError := errors.New("Any error")

	t.Run("updateKeycloakUser", func(t *testing.T) {
		t.Run("Fails to get access token", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideToken(validationCtx.ctx).Return("", anyError)
			err := component.updateKeycloakUser(validationCtx)
			assert.Equal(t, anyError, err)
		})
		t.Run("Fails to update user", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideToken(validationCtx.ctx).Return(accessToken, nil)
			mocks.keycloakClient.EXPECT().UpdateUser(accessToken, validationCtx.realmName, validationCtx.userID, gomock.Any()).Return(anyError)
			err := component.updateKeycloakUser(validationCtx)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			// already got an access token : won't retry
			mocks.keycloakClient.EXPECT().UpdateUser(accessToken, validationCtx.realmName, validationCtx.userID, gomock.Any()).Return(nil)
			err := component.updateKeycloakUser(validationCtx)
			assert.Nil(t, err)
		})
	})

	t.Run("Archive user", func(t *testing.T) {
		validationCtx.accessToken = &accessToken
		validationCtx.kcUser = nil
		t.Run("get user from keycloak fails", func(t *testing.T) {
			mocks.keycloakClient.EXPECT().GetUser(accessToken, validationCtx.realmName, validationCtx.userID).Return(kc.UserRepresentation{}, anyError)
			component.archiveUser(validationCtx)
		})
		mocks.keycloakClient.EXPECT().GetUser(accessToken, validationCtx.realmName, validationCtx.userID).Return(kc.UserRepresentation{}, nil).AnyTimes()

		t.Run("success", func(t *testing.T) {
			mocks.archiveDB.EXPECT().StoreUserDetails(validationCtx.ctx, validationCtx.realmName, gomock.Any())
			component.archiveUser(validationCtx)
		})
	})
}

func TestGetGroupsOfUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createComponentMocks(mockCtrl)
	component := mocks.createComponent()

	accessToken := "TOKEN=="
	realmName := "master"
	userID := "789-789-456"
	ctx := context.Background()

	t.Run("Get groups with succces", func(t *testing.T) {
		id := "1234-7454-4516"
		name := "client name"

		kcGroupRep := kc.GroupRepresentation{
			ID:   &id,
			Name: &name,
		}

		var kcGroupsRep []kc.GroupRepresentation
		kcGroupsRep = append(kcGroupsRep, kcGroupRep)

		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return(kcGroupsRep, nil)

		apiGroupsRep, err := component.GetGroupsOfUser(ctx, "master", userID)

		apiGroupRep := apiGroupsRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiGroupRep.ID)
		assert.Equal(t, name, *apiGroupRep.Name)
	})

	t.Run("Error accessToken", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, fmt.Errorf("Unexpected error"))

		_, err := component.GetGroupsOfUser(ctx, "master", userID)
		assert.NotNil(t, err)
	})
	t.Run("Error accessToken", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return([]kc.GroupRepresentation{}, fmt.Errorf("Unexpected error"))

		_, err := component.GetGroupsOfUser(ctx, "master", userID)
		assert.NotNil(t, err)
	})
}
