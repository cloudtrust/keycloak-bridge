package communications

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/communications"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetActionsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockCommunicationsComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetActionsEndpoint(mockCommunicationsComponent)

	var ctx = context.Background()

	mockCommunicationsComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil).Times(1)
	var res, err = e(ctx, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestSendEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockCommunicationsComponent = mock.NewComponent(mockCtrl)

	var e = MakeSendEmailEndpoint(mockCommunicationsComponent)

	var realm = "master"
	var ctx = context.Background()

	// No error
	{
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm

		emailJSON, _ := json.Marshal(emailForTest)
		req[reqBody] = string(emailJSON)

		mockCommunicationsComponent.EXPECT().SendEmail(ctx, realm, emailForTest).Return(nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	}

	// Error - Cannot unmarshall
	{
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}

	// Error - Keycloak client error
	{
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		emailJSON, _ := json.Marshal(emailForTest)
		req[reqBody] = string(emailJSON)

		mockCommunicationsComponent.EXPECT().SendEmail(ctx, realm, emailForTest).Return(fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}
}

func TestSendSMSEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockCommunicationsComponent = mock.NewComponent(mockCtrl)

	var e = MakeSendSMSEndpoint(mockCommunicationsComponent)

	var realm = "master"
	var ctx = context.Background()

	// No error
	{
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm

		smsJSON, _ := json.Marshal(smsForTest)
		req[reqBody] = string(smsJSON)

		mockCommunicationsComponent.EXPECT().SendSMS(ctx, realm, smsForTest).Return(nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	}

	// Error - Cannot unmarshall
	{
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}

	// Error - Keycloak client error
	{
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		smsJSON, _ := json.Marshal(smsForTest)
		req[reqBody] = string(smsJSON)

		mockCommunicationsComponent.EXPECT().SendSMS(ctx, realm, smsForTest).Return(fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}
}
