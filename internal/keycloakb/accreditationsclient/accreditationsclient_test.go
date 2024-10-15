package accreditationsclient

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNotifyCheck(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	accreditationsClient := MakeAccreditationsServiceClient(mockHTTPClient)
	ctx := context.Background()
	expectedError := errors.New("Test error")
	correlationID := "TestCorrelationID"

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHTTPClient.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any())

		err := accreditationsClient.NotifyCheck(ctx, CheckRepresentation{})
		assert.Nil(t, err)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHTTPClient.EXPECT().Put(gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedError)

		err := accreditationsClient.NotifyCheck(ctx, CheckRepresentation{})
		assert.NotNil(t, err)
	})
}

func TestNotifyUpdate(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	accreditationsClient := MakeAccreditationsServiceClient(mockHTTPClient)
	ctx := context.Background()
	expectedError := errors.New("Test error")
	correlationID := "TestCorrelationID"

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHTTPClient.EXPECT().Post(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		_, err := accreditationsClient.NotifyUpdate(ctx, UpdateNotificationRepresentation{})
		assert.Nil(t, err)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHTTPClient.EXPECT().Post(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", expectedError)

		_, err := accreditationsClient.NotifyUpdate(ctx, UpdateNotificationRepresentation{})
		assert.NotNil(t, err)
	})
}

func TestGetChecks(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	accreditationsClient := MakeAccreditationsServiceClient(mockHTTPClient)
	ctx := context.Background()
	expectedError := errors.New("Test error")
	correlationID := "TestCorrelationID"
	realm := "testRealm"
	userID := "userID"

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		_, err := accreditationsClient.GetChecks(ctx, realm, userID)
		assert.Nil(t, err)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedError)

		_, err := accreditationsClient.GetChecks(ctx, realm, userID)
		assert.NotNil(t, err)
	})
}

func TestGetPendingChecks(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	accreditationsClient := MakeAccreditationsServiceClient(mockHTTPClient)
	ctx := context.Background()
	expectedError := errors.New("Test error")
	correlationID := "TestCorrelationID"
	realm := "testRealm"
	userID := "userID"

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		_, err := accreditationsClient.GetPendingChecks(ctx, realm, userID)
		assert.Nil(t, err)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedError)

		_, err := accreditationsClient.GetPendingChecks(ctx, realm, userID)
		assert.NotNil(t, err)
	})
}

func TestGetIdentityChecksByNature(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	accreditationsClient := MakeAccreditationsServiceClient(mockHTTPClient)
	ctx := context.Background()
	expectedError := errors.New("Test error")
	correlationID := "TestCorrelationID"
	realm := "testRealm"

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		_, err := accreditationsClient.GetIdentityChecksByNature(ctx, realm)
		assert.Nil(t, err)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedError)

		_, err := accreditationsClient.GetIdentityChecksByNature(ctx, realm)
		assert.NotNil(t, err)
	})
}
