package validation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
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
	req[PrmRealm] = realm
	req[PrmUserID] = userID

	mockComponent.EXPECT().GetUser(ctx, realm, userID).Return(api.UserRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestUpdateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeUpdateUserEndpoint(mockComponent)
	var userID = "1234-452-4578"
	var realm = "realm"
	var ctx = context.Background()

	t.Run("No error", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		var req = map[string]string{PrmRealm: realm, PrmUserID: userID, ReqBody: string(userJSON)}

		mockComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Invalid input", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{Gender: ptr("unknown")})
		var req = map[string]string{PrmRealm: realm, PrmUserID: userID, ReqBody: string(userJSON)}

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var req = map[string]string{PrmRealm: realm, PrmUserID: userID, ReqBody: string("userJSON")}

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestCreateCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeCreateCheckEndpoint(mockComponent)
	var ctx = context.Background()
	var userID = "12345678-5824-5555-5656-123456789654"
	var realm = "realm"
	var operator = "operator"
	var datetime = time.Now()
	var status = "SUCCESS"
	var typeCheck = "IDENTITY_CHECK"
	var nature = "PHYSICAL"
	var proofType = "ZIP"
	var proofData = []byte("data")

	t.Run("No error", func(t *testing.T) {
		checkJSON, _ := json.Marshal(api.CheckRepresentation{
			UserID:    &userID,
			Operator:  &operator,
			DateTime:  &datetime,
			Status:    &status,
			Type:      &typeCheck,
			Nature:    &nature,
			ProofType: &proofType,
			ProofData: &proofData,
		})
		var req = map[string]string{
			PrmRealm:  realm,
			PrmUserID: userID,
			ReqBody:   string(checkJSON),
		}

		mockComponent.EXPECT().CreateCheck(ctx, realm, userID, gomock.Any()).Return(nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("Invalid input", func(t *testing.T) {
		checkJSON, _ := json.Marshal(api.CheckRepresentation{})
		var req = map[string]string{
			PrmRealm:  realm,
			PrmUserID: userID,
			ReqBody:   string(checkJSON),
		}

		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var req = make(map[string]string)
		req[PrmUserID] = userID
		req[ReqBody] = string("userJSON")

		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
}
