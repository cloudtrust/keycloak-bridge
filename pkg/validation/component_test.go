package validation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/configuration"
	log "github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation/mock"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	keycloakClient *mock.KeycloakClient
	usersDB        *mock.UsersDetailsDBModule
	archiveDB      *mock.ArchiveDBModule
	eventsDB       *mock.EventsDBModule
	tokenProvider  *mock.TokenProvider
	accreditations *mock.AccreditationsModule
	configDB       *mock.ConfigurationDBModule
}

func createComponentMocks(mockCtrl *gomock.Controller) componentMocks {
	return componentMocks{
		keycloakClient: mock.NewKeycloakClient(mockCtrl),
		usersDB:        mock.NewUsersDetailsDBModule(mockCtrl),
		archiveDB:      mock.NewArchiveDBModule(mockCtrl),
		eventsDB:       mock.NewEventsDBModule(mockCtrl),
		tokenProvider:  mock.NewTokenProvider(mockCtrl),
		accreditations: mock.NewAccreditationsModule(mockCtrl),
		configDB:       mock.NewConfigurationDBModule(mockCtrl),
	}
}

func (m *componentMocks) createComponent() *component {
	return NewComponent(m.keycloakClient, m.tokenProvider, m.usersDB, m.archiveDB, m.eventsDB, m.accreditations, m.configDB, log.NewNopLogger()).(*component)
}

func TestGetUserComponent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var accessToken = "abcd-1234"
	var realm = "my-realm"
	var userID = ""
	var anyError = errors.New("an error")
	var ctx = context.Background()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	t.Run("Fails to retrieve token for technical user", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", kcError)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUser from Keycloak fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		var kcError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetAdminConfiguration fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, anyError)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("Missing GLN", func(t *testing.T) {
		var bTrue = true
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{ShowGlnEditing: &bTrue}, nil)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})
	mocks.configDB.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, nil).AnyTimes()

	t.Run("GetUser from DB fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		var dbError = errors.New("DB error")
		mocks.usersDB.EXPECT().GetUserDetails(ctx, realm, userID).Return(dto.DBUser{}, dbError)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("No user found in DB", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, realm, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.Nil(t, err)
	})

	t.Run("Date parsing error", func(t *testing.T) {
		var expirationDate = "01.01-2020"
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, realm, userID).Return(dto.DBUser{
			IDDocumentExpiration: &expirationDate,
		}, nil)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.NotNil(t, err)
	})

	t.Run("Happy path", func(t *testing.T) {
		var expirationDate = "01.01.2020"
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, realm, userID).Return(dto.DBUser{
			IDDocumentExpiration: &expirationDate,
		}, nil)
		var _, err = component.GetUser(ctx, realm, userID)
		assert.Nil(t, err)
	})

}

func TestUpdateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var targetRealm = "cloudtrust"
	var userID = "abc789def"
	var accessToken = "abcdef"
	var ctx = context.TODO()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	t.Run("Fails to retrieve token for technical user", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		var kcError = errors.New("kc error")
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", kcError)
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("No update needed", func(t *testing.T) {
		var user = api.UserRepresentation{}
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.Nil(t, err)
	})

	t.Run("Fails to update user in DB", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		var dbError = errors.New("db error")
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(dbError)
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.NotNil(t, err)
	})
	mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dto.DBUser{
		UserID: &userID,
	}, nil).AnyTimes()
	mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealm, gomock.Any()).Return(nil).AnyTimes()

	t.Run("Fails to get user from KC", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		var kcError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, kcError)
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.NotNil(t, err)
	})
	mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil).AnyTimes()

	t.Run("Fails to update user in KC", func(t *testing.T) {
		var date = time.Now()
		var user = api.UserRepresentation{
			BirthDate: &date,
		}
		var kcError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("Fails to update user in KC", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		var kcError = errors.New("kc error")
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.NotNil(t, err)
	})
	mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil).AnyTimes()

	t.Run("Failure to store event", func(t *testing.T) {
		var date = time.Now()
		var user = api.UserRepresentation{
			FirstName:            ptr("newFirstname"),
			IDDocumentExpiration: &date,
		}
		var e = errors.New("error")
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(e)
		mocks.archiveDB.EXPECT().StoreUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.Nil(t, err)
	})
	mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mocks.archiveDB.EXPECT().StoreUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)

	t.Run("Successful update", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		var err = component.UpdateUser(ctx, targetRealm, userID, user)
		assert.Nil(t, err)
	})
}

func TestCreateCheck(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var targetRealm = "cloudtrust"
	var userID = "abc789def"
	var accessToken = "the-access-token"
	var ctx = context.TODO()
	var datetime = time.Now()
	var check = api.CheckRepresentation{
		Operator: ptr("operator"),
		DateTime: &datetime,
		Status:   ptr("status"),
	}

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	t.Run("Fails to store check in DB", func(t *testing.T) {
		var dbError = errors.New("db error")
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(dbError)
		var err = component.CreateCheck(ctx, targetRealm, userID, check)
		assert.NotNil(t, err)
	})

	t.Run("Can't get access token", func(t *testing.T) {
		check.Status = ptr("SUCCESS")
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", errors.New("no token"))
		var err = component.CreateCheck(ctx, targetRealm, userID, check)
		assert.NotNil(t, err)
	})
	t.Run("Accreditation module fails", func(t *testing.T) {
		var kcUser kc.UserRepresentation
		check.Status = ptr("SUCCESS")
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, keycloakb.CredsIDNow).Return(kcUser, 0, errors.New("Accreds failed"))
		var err = component.CreateCheck(ctx, targetRealm, userID, check)
		assert.NotNil(t, err)
	})

	t.Run("Success w/o accreditations", func(t *testing.T) {
		check.Status = ptr("FRAUD_SUSPICION_CONFIRMED")
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dto.DBUser{}, nil)
		mocks.archiveDB.EXPECT().StoreUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		var err = component.CreateCheck(ctx, targetRealm, userID, check)
		assert.Nil(t, err)
	})
	t.Run("Computed accreditations, fails to store them in Keycloak", func(t *testing.T) {
		var kcUser kc.UserRepresentation
		check.Status = ptr("SUCCESS")
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, keycloakb.CredsIDNow).Return(kcUser, 1, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, kcUser).Return(errors.New("KC fails"))
		mocks.keycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.usersDB.EXPECT().GetUserDetails(ctx, targetRealm, userID).Return(dto.DBUser{}, nil)
		mocks.archiveDB.EXPECT().StoreUserDetails(ctx, targetRealm, gomock.Any()).Return(nil)
		var err = component.CreateCheck(ctx, targetRealm, userID, check)
		assert.NotNil(t, err)
	})
	t.Run("Success with accreditations", func(t *testing.T) {
		var kcUser kc.UserRepresentation
		check.Status = ptr("SUCCESS")
		mocks.usersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, keycloakb.CredsIDNow).Return(kcUser, 1, nil)
		mocks.keycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, kcUser).Return(nil)
		mocks.eventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		var err = component.CreateCheck(ctx, targetRealm, userID, check)
		assert.Nil(t, err)
	})
}

func ptr(value string) *string {
	return &value
}

func TestValidationContext(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	var validationCtx = &validationContext{
		ctx:       context.TODO(),
		realmName: "my-realm",
		userID:    "abcd-4567",
		kcUser:    &kc.UserRepresentation{},
	}
	var accessToken = "abcd1234.efgh.5678ijkl"
	var anyError = errors.New("Any error")

	t.Run("updateKeycloakUser", func(t *testing.T) {
		t.Run("Fails to get access token", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideToken(validationCtx.ctx).Return("", anyError)
			var err = component.updateKeycloakUser(validationCtx)
			assert.Equal(t, anyError, err)
		})
		t.Run("Fails to update user", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideToken(validationCtx.ctx).Return(accessToken, nil)
			mocks.keycloakClient.EXPECT().UpdateUser(accessToken, validationCtx.realmName, validationCtx.userID, gomock.Any()).Return(anyError)
			var err = component.updateKeycloakUser(validationCtx)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			// already got an access token : won't retry
			mocks.keycloakClient.EXPECT().UpdateUser(accessToken, validationCtx.realmName, validationCtx.userID, gomock.Any()).Return(nil)
			var err = component.updateKeycloakUser(validationCtx)
			assert.Nil(t, err)
		})
	})

	t.Run("getUserWithAccreditations", func(t *testing.T) {
		validationCtx.accessToken = nil
		validationCtx.kcUser = nil
		t.Run("Fails to get access token", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideToken(validationCtx.ctx).Return("", anyError)
			var _, err = component.getUserWithAccreditations(validationCtx)
			assert.Equal(t, anyError, err)
		})
		t.Run("Fails to get user/accreditations", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideToken(validationCtx.ctx).Return(accessToken, nil)
			mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(validationCtx.ctx, accessToken, validationCtx.realmName,
				validationCtx.userID, gomock.Any()).Return(kc.UserRepresentation{}, 0, anyError)
			var _, err = component.getUserWithAccreditations(validationCtx)
			assert.Equal(t, anyError, err)
		})
		t.Run("Success", func(t *testing.T) {
			// already got an access token : won't retry
			mocks.accreditations.EXPECT().GetUserAndPrepareAccreditations(validationCtx.ctx, accessToken, validationCtx.realmName,
				validationCtx.userID, gomock.Any()).Return(kc.UserRepresentation{}, 0, nil)
			var _, err = component.getUserWithAccreditations(validationCtx)
			assert.Nil(t, err)
		})
	})

	t.Run("Archive user", func(t *testing.T) {
		validationCtx.accessToken = &accessToken
		validationCtx.kcUser = nil
		validationCtx.dbUser = nil
		t.Run("get user from keycloak fails", func(t *testing.T) {
			mocks.keycloakClient.EXPECT().GetUser(accessToken, validationCtx.realmName, validationCtx.userID).Return(kc.UserRepresentation{}, anyError)
			component.archiveUser(validationCtx, nil)
		})
		mocks.keycloakClient.EXPECT().GetUser(accessToken, validationCtx.realmName, validationCtx.userID).Return(kc.UserRepresentation{}, nil).AnyTimes()

		t.Run("get user from DB fails", func(t *testing.T) {
			mocks.usersDB.EXPECT().GetUserDetails(validationCtx.ctx, validationCtx.realmName, validationCtx.userID).Return(dto.DBUser{}, anyError)
			component.archiveUser(validationCtx, nil)
		})
		mocks.usersDB.EXPECT().GetUserDetails(validationCtx.ctx, validationCtx.realmName, validationCtx.userID).Return(dto.DBUser{}, nil).AnyTimes()

		t.Run("success", func(t *testing.T) {
			mocks.archiveDB.EXPECT().StoreUserDetails(validationCtx.ctx, validationCtx.realmName, gomock.Any())
			component.archiveUser(validationCtx, []dto.DBCheck{})
		})
	})
}
