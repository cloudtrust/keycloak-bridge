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
	req[prmRealm] = realm
	req[prmUserID] = userID

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
	var transactionID = "transaactionID"
	var ctx = context.Background()

	t.Run("No error", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		var req = map[string]string{prmRealm: realm, prmUserID: userID, prmTxnID: transactionID, reqBody: string(userJSON)}

		mockComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any(), transactionID).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("No error, no txnID", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string(userJSON)}

		mockComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any(), "txnID not available").Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Invalid input", func(t *testing.T) {
		userJSON, _ := json.Marshal(api.UserRepresentation{Gender: ptr("unknown")})
		var req = map[string]string{prmRealm: realm, prmUserID: userID, reqBody: string(userJSON)}

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
			prmRealm:  realm,
			prmUserID: userID,
			reqBody:   string(checkJSON),
		}

		mockComponent.EXPECT().CreateCheck(ctx, realm, userID, gomock.Any(), gomock.Any()).Return(nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("Invalid input", func(t *testing.T) {
		checkJSON, _ := json.Marshal(api.CheckRepresentation{})
		var req = map[string]string{
			prmRealm:  realm,
			prmUserID: userID,
			reqBody:   string(checkJSON),
		}

		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var req = make(map[string]string)
		req[prmUserID] = userID
		req[reqBody] = string("userJSON")

		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestMakeCreatePendingCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)
	var e = MakeCreatePendingCheckEndpoint(mockComponent)
	var realm = "the-realm"
	var userID = "user-id"
	var req = map[string]string{prmRealm: realm, prmUserID: userID}
	var ctx = context.TODO()

	t.Run("Invalid JSON", func(t *testing.T) {
		req[reqBody] = "{{"
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Invalid parameters in body", func(t *testing.T) {
		req[reqBody] = `{"nature":null}`
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Valid request", func(t *testing.T) {
		req[reqBody] = `{"nature":"check"}`
		mockComponent.EXPECT().CreatePendingCheck(ctx, realm, userID, gomock.Any()).Return(nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestMakeDeletePendingCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)
	var e = MakeDeletePendingCheckEndpoint(mockComponent)
	var realm = "the-realm"
	var userID = "user-id"
	var pendingCheck = "pending-check"
	var req = map[string]string{prmRealm: realm, prmUserID: userID, prmPendingCheck: pendingCheck}
	var ctx = context.TODO()

	mockComponent.EXPECT().DeletePendingCheck(ctx, realm, userID, pendingCheck)
	var _, err = e(ctx, req)
	assert.Nil(t, err)
}
