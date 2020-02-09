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
	var ctx = context.Background()
	var req = make(map[string]string)
	req["userID"] = userID

	mockComponent.EXPECT().GetUser(ctx, userID).Return(api.UserRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestUpdateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeUpdateUserEndpoint(mockComponent)

	t.Run("No error", func(t *testing.T) {
		var userID = "1234-452-4578"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["userID"] = userID
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		req["body"] = string(userJSON)

		mockComponent.EXPECT().UpdateUser(ctx, userID, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var userID = "1234-452-4578"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["userID"] = userID
		req["body"] = string("userJSON")

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

	t.Run("No error", func(t *testing.T) {
		var ctx = context.Background()
		var req = make(map[string]string)

		var userID = "12345678-5824-5555-5656-123456789654"
		var operator = "operator"
		var datetime = time.Now()
		var status = "SUCCESS"
		var typeCheck = "IDENTITY_CHECK"
		var nature = "PHYSICAL"
		var proofType = "ZIP"
		var proofData = []byte("data")

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

		req["userID"] = userID
		req["body"] = string(checkJSON)

		mockComponent.EXPECT().CreateCheck(ctx, userID, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var userID = "12345678-5824-5555-5656-123456789654"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["userID"] = userID
		req["body"] = string("userJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}
