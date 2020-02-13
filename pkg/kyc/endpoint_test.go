package kyc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeGetActionsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var m = map[string]string{}
	var expectedError = errors.New("get-actions")

	t.Run("GetActions - success case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetActions(gomock.Any()).Return([]apikyc.ActionRepresentation{}, nil)
		_, err := MakeGetActionsEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("GetActions - failure case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetActions(gomock.Any()).Return([]apikyc.ActionRepresentation{}, expectedError)
		_, err := MakeGetActionsEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Equal(t, expectedError, err)
	})
}

func TestMakeGetUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var realm = "master"
	var userID = "user1234"
	var m = map[string]string{"realm": realm, "userId": userID}
	var expectedError = errors.New("get-user")

	t.Run("GetUser - success case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUser(gomock.Any(), userID).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("GetUser - failure case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUser(gomock.Any(), userID).Return(apikyc.UserRepresentation{}, expectedError)
		_, err := MakeGetUserEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Equal(t, expectedError, err)
	})
}

func TestMakeGetUserByUsernameEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var realm = "master"
	var username = "user1234"
	var groupIDList = "group1,group2,group3"
	var groupIDs = strings.Split(groupIDList, ",")
	var m = map[string]string{"realm": realm, "username": username, "groupIds": groupIDList}
	var expectedError = errors.New("get-user")

	t.Run("GetUserByUsername - success case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserByUsername(gomock.Any(), username, groupIDs).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserByUsernameEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("GetUserByUsername - failure case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserByUsername(gomock.Any(), username, groupIDs).Return(apikyc.UserRepresentation{}, expectedError)
		_, err := MakeGetUserByUsernameEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Equal(t, expectedError, err)
	})

	t.Run("GetUserByUsername - missing groupIDs", func(t *testing.T) {
		var missingGroupIDs = map[string]string{"realm": realm, "username": username}
		_, err := MakeGetUserByUsernameEndpoint(mockKYCComponent)(context.Background(), missingGroupIDs)
		assert.NotNil(t, err)
	})
}

func TestMakeValidateUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var realm = "master"
	var first = "John"
	var last = "Doe"
	var userID = "ux467913"
	var user = apikyc.UserRepresentation{UserID: &userID, FirstName: &first, LastName: &last}
	var m = map[string]string{}

	t.Run("ValidateUser - success case", func(t *testing.T) {
		var bytes, _ = json.Marshal(user)
		m["realm"] = realm
		m["body"] = string(bytes)
		m["userId"] = userID
		mockKYCComponent.EXPECT().ValidateUser(gomock.Any(), userID, user).Return(nil).Times(1)
		_, err := MakeValidateUserEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("ValidateUser - failure case", func(t *testing.T) {
		m["realm"] = realm
		m["body"] = "{"
		_, err := MakeValidateUserEndpoint(mockKYCComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})
}
