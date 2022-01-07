package keycloakb

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gentleman.v2/plugin"
)

func TestGetBalance(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHttpClient := mock.NewHttpClient(mockCtrl)
	accountingClient := MakeAccountingClient(mockHttpClient)
	var ctx = context.Background()
	var expectedError = errors.New("Test error")

	var realmName = "Test"
	var userID = "394b0730-628f-11ec-9211-0242ac120005"
	var service = "VIDEO_IDENTIFICATION"
	var correlationID = "TestCorrelationID"
	var expectedBalance = float32(10)

	ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)

	t.Run("SUCCESS", func(t *testing.T) {
		mockHttpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(data interface{}, plugins ...plugin.Plugin) error {
			data.(*AccountingBalance).Balance = &expectedBalance
			return nil
		}).Times(1)

		balance, err := accountingClient.GetBalance(ctx, realmName, userID, service)
		assert.Nil(t, err)
		assert.Equal(t, expectedBalance, balance)
	})

	t.Run("FAILURE", func(t *testing.T) {
		mockHttpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedError).Times(1)

		balance, err := accountingClient.GetBalance(ctx, realmName, userID, service)
		assert.NotNil(t, err)
		assert.Equal(t, float32(0), balance)
	})
}
