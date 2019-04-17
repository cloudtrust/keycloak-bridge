package management

//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/security"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestDeny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var credentialID = "741-865-741"
	var userUsername = "toto"
	var userGroups = []string{"customer"}
	var groupName = "titi"

	var roleName = "role"

	var pass = "P@ssw0rd"

	mockKeycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}, nil).AnyTimes()

	var user = api.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}

	var role = api.RoleRepresentation{
		Id:   &roleID,
		Name: &roleName,
	}

	var roles = []api.RoleRepresentation{role}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	// Nothing allowed
	{
		var authorisations, err = security.NewAuthorizationManager(mockKeycloakClient, `{}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		_, err = authorisationMW.GetRealms(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetRealm(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetClient(ctx, realmName, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetClients(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorisationMW.DeleteUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorisationMW.UpdateUser(ctx, realmName, userID, user)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetUsers(ctx, realmName, groupName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.CreateUser(ctx, realmName, user)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetUserAccountStatus(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorisationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetRealmRolesForUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorisationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorisationMW.SendVerifyEmail(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetCredentialsForUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorisationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetRoles(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetRole(ctx, realmName, roleID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorisationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Equal(t, security.ForbiddenError{}, err)
	}
}

func TestAllowed(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var credentialID = "7845-785-1545"
	var userUsername = "toto"
	var userGroups = []string{"customer"}

	var roleName = "role"

	var groupName = "titi"

	var pass = "P@ssw0rd"

	mockKeycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}, nil).AnyTimes()

	var user = api.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}

	var role = api.RoleRepresentation{
		Id:   &roleID,
		Name: &roleName,
	}

	var roles = []api.RoleRepresentation{role}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	// Nothing allowed
	{
		var authorisations, err = security.NewAuthorizationManager(mockKeycloakClient, `{"master":
			{
				"toe": {
					"GetRealms": {"*": {}},
					"GetRealm": {"*": {"*": {} }},
					"GetClient": {"*": {"*": {} }},
					"GetClients": {"*": {"*": {} }},
					"DeleteUser": {"*": {"*": {} }},
					"GetUser": {"*": {"*": {} }},
					"UpdateUser": {"*": {"*": {} }},
					"GetUsers": {"*": {"*": {} }},
					"CreateUser": {"*": {"*": {} }},
					"GetUserAccountStatus": {"*": {"*": {} }},
					"GetClientRolesForUser": {"*": {"*": {} }},
					"AddClientRolesToUser": {"*": {"*": {} }},
					"GetRealmRolesForUser": {"*": {"*": {} }},
					"ResetPassword": {"*": {"*": {} }},
					"SendVerifyEmail": {"*": {"*": {} }},
					"GetCredentialsForUser": {"*": {"*": {} }},
					"DeleteCredentialsForUser": {"*": {"*": {} }},
					"GetRoles": {"*": {"*": {} }},
					"GetRole": {"*": {"*": {} }},
					"GetClientRoles": {"*": {"*": {} }},
					"CreateClientRole": {"*": {"*": {} }}
				}
			}
		}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		mockManagementComponent.EXPECT().GetRealms(ctx).Return([]api.RealmRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRealms(ctx)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealm(ctx, realmName).Return(api.RealmRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRealm(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClient(ctx, realmName, clientID).Return(api.ClientRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClient(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClients(ctx, realmName).Return([]api.ClientRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClients(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteUser(ctx, realmName, userID).Return(nil).Times(1)
		err = authorisationMW.DeleteUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUser(ctx, realmName, userID).Return(api.UserRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateUser(ctx, realmName, userID, user).Return(nil).Times(1)
		err = authorisationMW.UpdateUser(ctx, realmName, userID, user)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUsers(ctx, realmName, groupName).Return([]api.UserRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetUsers(ctx, realmName, groupName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateUser(ctx, realmName, user).Return("", nil).Times(1)
		_, err = authorisationMW.CreateUser(ctx, realmName, user)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUserAccountStatus(ctx, realmName, userID).Return(map[string]bool{"enabled": true}, nil).Times(1)
		_, err = authorisationMW.GetUserAccountStatus(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRolesForUser(ctx, realmName, userID, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realmName, userID, clientID, roles).Return(nil).Times(1)
		err = authorisationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealmRolesForUser(ctx, realmName, userID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRealmRolesForUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realmName, userID, password).Return(nil).Times(1)
		err = authorisationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendVerifyEmail(ctx, realmName, userID).Return(nil).Times(1)
		err = authorisationMW.SendVerifyEmail(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetCredentialsForUser(ctx, realmName, userID).Return([]api.CredentialRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetCredentialsForUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realmName, userID, credentialID).Return(nil).Times(1)
		err = authorisationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRoles(ctx, realmName).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRoles(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRole(ctx, realmName, roleID).Return(api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRole(ctx, realmName, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRoles(ctx, realmName, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realmName, clientID, role).Return("", nil).Times(1)
		_, err = authorisationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Nil(t, err)
	}
}
