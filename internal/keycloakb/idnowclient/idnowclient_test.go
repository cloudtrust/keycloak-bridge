package idnowclient

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetIdentificationsByType(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	idnowClient := MakeIdnowServiceClient(mockHTTPClient)
	ctx := context.Background()
	expectedError := errors.New("Test error")
	correlationID := "TestCorrelationID"
	realm := "testRealm"

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
