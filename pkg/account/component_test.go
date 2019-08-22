package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func genericUpdatePasswordTest(t *testing.T, oldPasswd, newPasswd, confirmPassword string, kcCalls int, expectingError bool) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := mock.NewAccKeycloakClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockLogger := mock.NewLogger(mockCtrl)
	component := NewComponent(mockKeycloakClient, mockEventDBModule, mockLogger)

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

func TestUpdatePasswordWrongPwd(t *testing.T) {
	oldPasswd := "wrong prev10u5"
	newPasswd := "a p@55w0rd"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := mock.NewAccKeycloakClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockLogger := mock.NewLogger(mockCtrl)
	component := NewComponent(mockKeycloakClient, mockEventDBModule, mockLogger)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", fmt.Errorf("invalidPasswordExistingMessage")).Times(1)
	mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	err := component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd)

	assert.True(t, err != nil)

	mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", fmt.Errorf("invalid")).Times(1)
	mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	err = component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd)

	assert.True(t, err != nil)

	// password reset succeeded, but storing the event failed
	{
		mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username).Return(errors.New("error")).Times(1)
		m := map[string]interface{}{"event_name": "PASSWORD_RESET", database.CtEventRealmName: realm, database.CtEventUserID: userID, database.CtEventUsername: username}
		eventJSON, _ := json.Marshal(m)
		mockLogger.EXPECT().Error("err", "error", "event", string(eventJSON))
		err = component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd)
		assert.True(t, err == nil)

	}

}
