package communications

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/communications/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	reqScheme = "scheme"
)

func TestSendEmailEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockCommunicationsComponent := mock.NewComponent(mockCtrl)

	e := MakeSendEmailEndpoint(mockCommunicationsComponent)

	realm := "master"
	ctx := context.Background()

	t.Run("No Error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[prmRealm] = realm

		emailJSON, _ := json.Marshal(emailForTest)
		req[reqBody] = string(emailJSON)

		mockCommunicationsComponent.EXPECT().SendEmail(ctx, realm, emailForTest).Return(nil).Times(1)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Invalid emailRepresentation", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string(`{
			"Recipient":"toto",
			"theming":{
				"subjectKey":"cantRegisterSubject",
				"subjectParameters":[],
				"template":"template.ftl",
				"templateParameters":{
					"checkStatus":"STATUS"
				},
				"themeRealmName":"corporate"
			}}`)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[prmRealm] = realm
		emailJSON, _ := json.Marshal(emailForTest)
		req[reqBody] = string(emailJSON)

		mockCommunicationsComponent.EXPECT().SendEmail(ctx, realm, emailForTest).Return(fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestSendEmailToUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockCommunicationsComponent := mock.NewComponent(mockCtrl)

	e := MakeSendEmailToUserEndpoint(mockCommunicationsComponent)

	realm := "test"
	userID := "testerID"
	ctx := context.Background()

	t.Run("No Error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[prmRealm] = realm
		req[prmUserID] = userID

		emailJSON, _ := json.Marshal(emailForTest)
		req[reqBody] = string(emailJSON)

		mockCommunicationsComponent.EXPECT().SendEmailToUser(ctx, realm, userID, emailForTest).Return(nil).Times(1)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Invalid emailRepresentation", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string(`{
			"Recipient":"toto",
			"theming":{
				"subjectKey":"cantRegisterSubject",
				"subjectParameters":[],
				"template":"template.ftl",
				"templateParameters":{
					"checkStatus":"STATUS"
				},
				"themeRealmName":"corporate"
			}}`)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[prmRealm] = realm
		req[prmUserID] = userID
		emailJSON, _ := json.Marshal(emailForTest)
		req[reqBody] = string(emailJSON)

		mockCommunicationsComponent.EXPECT().SendEmailToUser(ctx, realm, userID, emailForTest).Return(fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestSendSMSEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockCommunicationsComponent := mock.NewComponent(mockCtrl)

	e := MakeSendSMSEndpoint(mockCommunicationsComponent)

	realm := "master"
	ctx := context.Background()

	t.Run("No Error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[prmRealm] = realm

		smsJSON, _ := json.Marshal(smsForTest)
		req[reqBody] = string(smsJSON)

		mockCommunicationsComponent.EXPECT().SendSMS(ctx, realm, smsForTest).Return(nil).Times(1)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Invalid SMSRepresentation", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string(`{
			"msidn":"notAPhoneNumber",
			"theming":{}
		}`)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[prmRealm] = realm
		smsJSON, _ := json.Marshal(smsForTest)
		req[reqBody] = string(smsJSON)

		mockCommunicationsComponent.EXPECT().SendSMS(ctx, realm, smsForTest).Return(fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
}
