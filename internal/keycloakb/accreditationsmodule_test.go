package keycloakb

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func createRealmAdminCred(typeValue, validity, condition string) configuration.RealmAdminAccreditation {
	return configuration.RealmAdminAccreditation{
		Type:      &typeValue,
		Validity:  &validity,
		Condition: &condition,
	}
}

const (
	duration1 = "2y"
	duration2 = "1w"
	duration3 = "6m"
)

func createRealmAdminConfig(condition string) configuration.RealmAdminConfiguration {
	var otherCondition = "no-" + condition
	var accreds = []configuration.RealmAdminAccreditation{
		createRealmAdminCred("SHADOW1", duration1, condition),
		createRealmAdminCred("SHADOW2", "1y", otherCondition),
		createRealmAdminCred("SHADOW3", duration2, condition),
		createRealmAdminCred("SHADOW4", "3y", otherCondition),
		createRealmAdminCred("SHADOW5", duration3, condition),
	}
	return configuration.RealmAdminConfiguration{Accreditations: accreds}
}

func TestIsUpdated(t *testing.T) {
	var empty = ""
	var formerValue = "former"
	var formerValueUppercased = "FORMER"
	var newValue = "new"

	assert.False(t, IsUpdated(nil, nil))
	assert.False(t, IsUpdated(nil, nil, nil, &empty))
	assert.False(t, IsUpdated(nil, nil, nil, &empty, nil, &formerValue))
	assert.False(t, IsUpdated(&formerValue, &formerValue))
	assert.False(t, IsUpdated(&formerValueUppercased, &formerValue))
	assert.True(t, IsUpdated(&newValue, nil))
	assert.True(t, IsUpdated(&newValue, &formerValue))
}

func TestRevokeAccreditations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var user = kc.UserRepresentation{}

	t.Run("No existing accreditations", func(t *testing.T) {
		var updated = RevokeAccreditations(&user)
		assert.Len(t, user.GetAttribute(constants.AttrbAccreditations), 0)
		assert.False(t, updated)
	})
	t.Run("Nothing changes", func(t *testing.T) {
		var accreds = []string{"a", "b", `{"type":"ONE", "expiryDate":"01.01.2015", "creationMillis":123456789, "revoked":true}`}
		user.SetAttribute(constants.AttrbAccreditations, accreds)
		var updated = RevokeAccreditations(&user)
		assert.Equal(t, accreds, user.GetAttribute(constants.AttrbAccreditations))
		assert.False(t, updated)
	})
	t.Run("Revoke one accreditation", func(t *testing.T) {
		var accreds = []string{`{"type":"ONE", "expiryDate":"01.01.2015"}`,
			`{"type":"TWO", "expiryDate":"01.01.2016"}`,
			`{"type":"THREE", "expiryDate":"01.01.2025"}`}
		user.SetAttribute(constants.AttrbAccreditations, accreds)
		var updated = RevokeAccreditations(&user)
		assert.Equal(t, accreds[0], user.GetAttribute(constants.AttrbAccreditations)[0])
		assert.Equal(t, accreds[1], user.GetAttribute(constants.AttrbAccreditations)[1])
		assert.NotEqual(t, accreds[2], user.GetAttribute(constants.AttrbAccreditations)[2])
		assert.True(t, updated)
	})
}

func TestGetUserAndPrepareAccreditations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloak = mock.NewAccredsKeycloakClient(mockCtrl)
	var mockConfDB = mock.NewConfigurationDBModule(mockCtrl)
	var logger = log.NewNopLogger()

	var accredsModule = NewAccreditationsModule(mockKeycloak, mockConfDB, logger)

	var ctx = context.TODO()
	var accessToken = "access-token"
	var realmName = "realm-name"
	var realmID = "the-realm-id"
	var userID = "the-user-id"
	var anyError = errors.New("I don't know")
	var condition = "physical"
	var otherCondition = "other"
	var kcRealm = kc.RealmRepresentation{ID: &realmID}
	var kcUser = kc.UserRepresentation{ID: &userID}

	t.Run("Keycloak.GetRealm fails", func(t *testing.T) {
		mockKeycloak.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{}, anyError)
		var _, _, err = accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, condition)
		assert.NotNil(t, err)
	})
	t.Run("Database.GetAdminConfiguration fails", func(t *testing.T) {
		mockKeycloak.EXPECT().GetRealm(accessToken, realmName).Return(kcRealm, nil)
		mockConfDB.EXPECT().GetAdminConfiguration(ctx, realmID).Return(configuration.RealmAdminConfiguration{}, anyError)
		var _, _, err = accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, condition)
		assert.NotNil(t, err)
	})
	t.Run("No condition matches", func(t *testing.T) {
		mockKeycloak.EXPECT().GetRealm(accessToken, realmName).Return(kcRealm, nil)
		mockConfDB.EXPECT().GetAdminConfiguration(ctx, realmID).Return(createRealmAdminConfig(otherCondition), nil)
		mockKeycloak.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, nil)
		var _, _, err = accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, condition)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, 500, err.(errorhandler.Error).Status)
	})
	t.Run("Invalid accreditation validity duration", func(t *testing.T) {
		var credsConf = createRealmAdminConfig(condition)
		var invalidDuration = "??"
		credsConf.Accreditations[0].Validity = &invalidDuration
		mockKeycloak.EXPECT().GetRealm(accessToken, realmName).Return(kcRealm, nil)
		mockConfDB.EXPECT().GetAdminConfiguration(ctx, realmID).Return(credsConf, nil)
		var _, _, err = accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, condition)
		assert.NotNil(t, err)
	})
	t.Run("Keycloak.GetUser fails", func(t *testing.T) {
		mockKeycloak.EXPECT().GetRealm(accessToken, realmName).Return(kcRealm, nil)
		mockConfDB.EXPECT().GetAdminConfiguration(ctx, realmID).Return(createRealmAdminConfig(condition), nil)
		mockKeycloak.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, anyError)
		var _, _, err = accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, condition)
		assert.NotNil(t, err)
	})
	t.Run("Accreditations creation is successful", func(t *testing.T) {
		kcUser.Attributes = nil
		mockKeycloak.EXPECT().GetRealm(accessToken, realmName).Return(kcRealm, nil)
		mockConfDB.EXPECT().GetAdminConfiguration(ctx, realmID).Return(createRealmAdminConfig(condition), nil)
		mockKeycloak.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
		var kcUser, count, err = accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, condition)
		assert.Nil(t, err)
		var accreds = kcUser.GetAttribute(constants.AttrbAccreditations)
		assert.Equal(t, 3, count)
		assert.Len(t, accreds, 3)
		sort.Strings(accreds)
		assert.Contains(t, accreds[0], "SHADOW1")
		assert.Contains(t, accreds[1], "SHADOW3")
		assert.Contains(t, accreds[2], "SHADOW5")
		assert.Contains(t, accreds[0], validation.AddLargeDuration(time.Now(), duration1).Format(dateLayout))
		assert.Contains(t, accreds[1], validation.AddLargeDuration(time.Now(), duration2).Format(dateLayout))
		assert.Contains(t, accreds[2], validation.AddLargeDuration(time.Now(), duration3).Format(dateLayout))
	})
}
