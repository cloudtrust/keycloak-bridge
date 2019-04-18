package security

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestCheckAuthorizationOnRealm(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var accessToken = "TOKEN=="
	var groups = []string{"toe", "svc"}

	// Authorized for all realm (test wildcard)
	{
		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"GetRealm": {"*": {} }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		err = authorizationManager.CheckAuthorizationOnTargetRealm(ctx, "GetRealm", "master")

		assert.Nil(t, err)
	}

	// Authorized for non admin realm
	{
		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"GetRealm": {"/": {} }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		err = authorizationManager.CheckAuthorizationOnTargetRealm(ctx, "GetRealm", "toto")
		assert.Nil(t, err)

		err = authorizationManager.CheckAuthorizationOnTargetRealm(ctx, "GetRealm", "master")
		assert.NotNil(t, err)
		assert.Equal(t, "ForbiddenError: Operation not permitted.", err.Error())

	}

	// Authorized for specific realm
	{
		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"GetRealm": {"master": {} }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		err = authorizationManager.CheckAuthorizationOnTargetRealm(ctx, "GetRealm", "master")
		assert.Nil(t, err)

		err = authorizationManager.CheckAuthorizationOnTargetRealm(ctx, "GetRealm", "other")
		assert.Equal(t, "ForbiddenError: Operation not permitted.", err.Error())
	}

	// Deny by default
	{
		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"CreateUser": {"master": {} }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		err = authorizationManager.CheckAuthorizationOnTargetRealm(ctx, "GetRealm", "master")
		assert.Equal(t, ForbiddenError{}, err)
	}
}

func TestCheckAuthorizationOnTargetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var accessToken = "TOKEN=="
	var groups = []string{"toe", "svc"}
	var realm = "master"

	// Authorized for all groups (test wildcard)
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"DeleteUser": {"master": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userID = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userID,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", "master", userID)
		assert.Nil(t, err)
	}

	// Test no groups assigned to targetUser
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"DeleteUser": {"master": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userID = "123-456-789"
		var userUsername = "toto"

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userID,
			Username: &userUsername,
		}, nil).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", "master", userID)
		assert.Equal(t, ForbiddenError{}, err)
	}

	// Test allowed only for non master realm
	{
		var targetRealm = "toto"
		var targetUserID = "123-456-789"

		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"DeleteUser": {"/": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userID = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userID,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", targetRealm, userID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetUser(accessToken, "master", targetUserID).Return(kc.UserRepresentation{
			Id:       &userID,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", "master", targetUserID)
		assert.Equal(t, ForbiddenError{}, err)
	}

	// Authorized for all realms (test wildcard) and all groups
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"DeleteUser": {"*": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", "master", targetUserID)
		assert.Nil(t, err)
	}

	// Test cannot GetUser infos
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"DeleteUser": {"*": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{}, fmt.Errorf("Error")).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", "master", targetUserID)
		assert.Equal(t, ForbiddenError{}, err)
	}

	// Test for a specific target group
	{
		var targetRealm = "toto"
		var targetUserID = "123-456-789"

		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"DeleteUser": {"toto": { "customer": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", targetRealm, targetUserID)
		assert.Nil(t, err)
	}

	// Deny
	{
		var targetRealm = "toto"
		var targetUserID = "123-456-789"

		var authorizationManager, err = NewAuthorizationManager(mockKeycloakClient, `{"master": {"toe": {"DeleteUser": {}} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		err = authorizationManager.CheckAuthorizationOnTargetUser(ctx, "DeleteUser", targetRealm, targetUserID)
		assert.Equal(t, ForbiddenError{}, err)
	}
}

func TestLoadAuthorizations(t *testing.T) {

	// Empty file
	{
		var jsonAuthz = ""
		_, err := loadAuthorizations(jsonAuthz)
		assert.NotNil(t, err)
		assert.Equal(t, "JSON structure expected.", err.Error())

		_, err = NewAuthorizationManager(nil, jsonAuthz)
		assert.NotNil(t, err)
		assert.Equal(t, "JSON structure expected.", err.Error())
	}

	// Empty JSON
	{
		var jsonAuthz = "{}"
		_, err := loadAuthorizations(jsonAuthz)
		assert.Nil(t, err)
	}

	// Wrong format
	{
		var jsonAuthz = "{sdf}ref"
		_, err := loadAuthorizations(jsonAuthz)
		assert.NotNil(t, err)
	}

	// Correct format
	{
		var jsonAuthz = `{
			"master":{
			  "toe_administrator":{
				"GetUsers": {
				  "master": {
					"*": {}
				  }
				},
				"CreateUser": {
				  "master": {
					"integrator_manager": {},
					"integrator_agent": {},
					"l2_support_manager": {},
					"l2_support_agent": {},
					"l3_support_manager": {},
					"l3_support_agent": {}
				  }
				}
			  },
			  "l3_support_agent": {}
			},
			"DEP":{
			  "product_administrator":{
				"GetUsers": {
				  "DEP": {
					"*": {}
				  }
				},
				"CreateUser": {
				  "DEP": {
					"l1_support_manager": {}
				  }
				}
			  },
			  "l1_support_manager": {
				"GetUsers": {
				  "DEP": {
					"l1_support_agent": {},
					"end_user": {}
				  }
				}
			  }
			}
		  }`

		authorizations, err := loadAuthorizations(jsonAuthz)
		assert.Nil(t, err)

		_, ok := authorizations["master"]["toe_administrator"]["GetUsers"]["master"]["*"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["master"]["toe_administrator"]["GetUsers"]["master"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["master"]["l3_support_agent"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["master"]["l3_support_agent"]["GetUsers"]["master"]
		assert.Equal(t, false, ok)

		_, ok = authorizations["DEP"]["l1_support_manager"]["GetUsers"]["DEP"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["DEP"]["l1_support_manager"]["GetUsers"]["DEP"]["end_user"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["DEP"]["l1_support_manager"]["GetUsers"]["DEP"]["end_user2"]
		assert.Equal(t, false, ok)
	}
}

