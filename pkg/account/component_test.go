package account

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service"
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
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, confirmPassword).Return("", nil).Times(kcCalls)
	mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(kcCalls)

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
