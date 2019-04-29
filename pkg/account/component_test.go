package account

//go:generate mockgen -destination=./mock/acc_keycloak_client.go -package=mock -mock_names=KeycloakClient=AccKeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/account KeycloakClient
//go:generate mockgen -destination=./mock/eventsdbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/keycloak-bridge/pkg/event EventsDBModule

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func genericUpdatePasswordTest(t *testing.T, oldPasswd, newPasswd, confirmPassword string, kcCalls int, expectingError bool) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := mock.NewAccKeycloakClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	component := NewComponent(mockKeycloakClient, mockEventDBModule)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), "access_token", accessToken)
	ctx = context.WithValue(ctx, "realm", realm)
	ctx = context.WithValue(ctx, "userId", userID)
	ctx = context.WithValue(ctx, "username", username)

	mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, confirmPassword).Return("", nil).Times(kcCalls)
	mockEventDBModule.EXPECT().Store(gomock.Any(), gomock.Any()).Times(kcCalls)

	err := component.UpdatePassword(ctx, oldPasswd, newPasswd, confirmPassword)

	assert.Equal(t, expectingError, err != nil)
}

func TestUpdatePasswordNoChange(t *testing.T) {
	passwd := "a p@55w0rd"
	genericUpdatePasswordTest(t, passwd, passwd, passwd, 0, true)
}

func TestUpdatePasswordBadConfirm(t *testing.T) {
	oldPasswd := "prev10u5"
	newPasswd := "a p@55w0rd"
	genericUpdatePasswordTest(t, oldPasswd, newPasswd, newPasswd+newPasswd, 0, true)
}

func TestUpdatePassword(t *testing.T) {
	oldPasswd := "prev10u5"
	newPasswd := "a p@55w0rd"
	genericUpdatePasswordTest(t, oldPasswd, newPasswd, newPasswd, 1, false)
}
