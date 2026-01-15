package validation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetUserEndpoint(mockComponent)

	var userID = "1234-452-4578"
	var realm = "realm"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockComponent.EXPECT().GetUser(ctx, realm, userID).Return(api.UserRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestUpdateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockComponent    = mock.NewComponent(mockCtrl)
		mockProfileCache = mock.NewUserProfileCache(mockCtrl)

		e             = MakeUpdateUserEndpoint(mockComponent, mockProfileCache)
		userID        = "1234-452-4578"
		realm         = "realm"
		transactionID = "transactionID"
		ctx           = context.TODO()
	)

	t.Run("No error", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		var req = map[string]string{prmRealm: realm, prmUserID: userID, prmTxnID: transactionID, reqBody: string(userJSON)}

		mockProfileCache.EXPECT().GetRealmUserProfile(gomock.Any(), realm).Return(kc.UserProfileRepresentation{}, nil)
		mockComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any(), &transactionID).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("No error, no txnID", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string(userJSON)}

		mockProfileCache.EXPECT().GetRealmUserProfile(gomock.Any(), realm).Return(kc.UserProfileRepresentation{}, nil)
		mockComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any(), nil).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Invalid input", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{Gender: ptr("unknown")})
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string(userJSON)}

		mockProfileCache.EXPECT().GetRealmUserProfile(gomock.Any(), realm).Return(kc.UserProfileRepresentation{}, errors.New(""))
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string("userJSON")}

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestUpdateUserAccreditationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeUpdateUserAccreditationsEndpoint(mockComponent)
	var userID = "1234-452-4578"
	var realm = "realm"
	var ctx = context.Background()

	t.Run("No error", func(t *testing.T) {
		accreditations := []api.AccreditationRepresentation{
			{
				Name:     ptr("test"),
				Validity: ptr("4y"),
			},
		}
		accreditationsJSON, _ := json.Marshal(accreditations)
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string(accreditationsJSON)}

		mockComponent.EXPECT().UpdateUserAccreditations(ctx, realm, userID, accreditations).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Invalid input", func(t *testing.T) {
		accreditationsJSON, _ := json.Marshal([]api.AccreditationRepresentation{
			{
				Name:     ptr("test"),
				Validity: ptr("4"),
			},
		})
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string(accreditationsJSON)}

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string("errorJSON")}

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetGroupsOfUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetGroupsOfUserEndpoint(mockComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockComponent.EXPECT().GetGroupsOfUser(ctx, realm, userID).Return([]api.GroupRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetRolessOfUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetRolesOfUserEndpoint(mockComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockComponent.EXPECT().GetRolesOfUser(ctx, realm, userID).Return([]api.RoleRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}
