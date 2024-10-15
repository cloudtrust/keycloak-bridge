package keycloakb

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"gopkg.in/h2non/gentleman.v2/plugin"
)

func TestGetBalance(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := mock.NewHTTPClient(mockCtrl)
	accountingClient := MakeAccountingClient(mockHTTPClient)
	ctx := context.Background()
	expectedError := errors.New("Test error")

	realmName := "Test"
	userID := "394b0730-628f-11ec-9211-0242ac120005"
	service := "VIDEO_IDENTIFICATION"
	correlationID := "TestCorrelationID"
	expectedBalance := float64(10)

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(data interface{}, plugins ...plugin.Plugin) error {
			data.(*AccountingBalance).Balance = &expectedBalance
			return nil
		}).Times(1)

		balance, err := accountingClient.GetBalance(ctx, realmName, userID, service)
		assert.Nil(t, err)
		assert.Equal(t, expectedBalance, balance)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHTTPClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedError).Times(1)

		_, err := accountingClient.GetBalance(ctx, realmName, userID, service)
		assert.NotNil(t, err)
	})
}
