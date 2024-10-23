package idnowclient

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetIdentificationsByType(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	idnowClient := MakeIdnowServiceClient(mockHTTPClient)
	var ctx = context.Background()
	var expectedError = errors.New("Test error")
	var correlationID = "TestCorrelationID"
	var realm = "testRealm"

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		_, err := idnowClient.GetIdentificationsByType(ctx, realm)
		assert.Nil(t, err)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedError)

		_, err := idnowClient.GetIdentificationsByType(ctx, realm)
		assert.NotNil(t, err)
	})
}
