package management

//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/management KeycloakClient

import (
	"context"
	"fmt"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetRealm(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Get realm with succces
	{
		var id = "1245"
		var keycloakVersion = "4.8.3"
		var realm = "master"
		var displayName = "Master"
		var enabled = true

		var kcRealmRep = kc.RealmRepresentation{
			Id:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		mockKeycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kcRealmRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiRealmRep, err := managementComponent.GetRealm(ctx, "master")

		var expectedAPIRealmRep = api.RealmRepresentation{
			Id:              &id,
			KeycloakVersion: &keycloakVersion,
			Realm:           &realm,
			DisplayName:     &displayName,
			Enabled:         &enabled,
		}

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIRealmRep, apiRealmRep)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetRealm(accessToken, realmName).Return(kc.RealmRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetRealm(ctx, "master")

		assert.NotNil(t, err)
	}
}

func TestGetClient(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Get client with succces
	{
		var id = "1245-1245-4578"
		var name = "clientName"
		var baseURL = "http://toto.com"
		var clientID = "client-id"
		var description = "description"
		var enabled = true

		var kcClientRep = kc.ClientRepresentation{
			Id:          &id,
			Name:        &name,
			BaseUrl:     &baseURL,
			ClientId:    &clientID,
			Description: &description,
			Enabled:     &enabled,
		}

		mockKeycloakClient.EXPECT().GetClient(accessToken, realmName, id).Return(kcClientRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiClientRep, err := managementComponent.GetClient(ctx, "master", id)

		var expectedAPIClientRep = api.ClientRepresentation{
			Id:          &id,
			Name:        &name,
			BaseUrl:     &baseURL,
			ClientId:    &clientID,
			Description: &description,
			Enabled:     &enabled,
		}

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIClientRep, apiClientRep)
	}

	//Error
	{
		var id = "1234-79894-7594"
		mockKeycloakClient.EXPECT().GetClient(accessToken, realmName, id).Return(kc.ClientRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetClient(ctx, "master", id)

		assert.NotNil(t, err)
	}
}

func TestGetClients(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Get clients with succces
	{
		var id = "1234-7894-58"
		var name = "clientName"
		var baseURL = "http://toto.com"
		var clientID = "client-id"
		var description = "description"
		var enabled = true

		var kcClientRep = kc.ClientRepresentation{
			Id:          &id,
			Name:        &name,
			BaseUrl:     &baseURL,
			ClientId:    &clientID,
			Description: &description,
			Enabled:     &enabled,
		}

		var kcClientsRep []kc.ClientRepresentation
		kcClientsRep = append(kcClientsRep, kcClientRep)

		mockKeycloakClient.EXPECT().GetClients(accessToken, realmName).Return(kcClientsRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiClientsRep, err := managementComponent.GetClients(ctx, "master")

		var expectedAPIClientRep = api.ClientRepresentation{
			Id:          &id,
			Name:        &name,
			BaseUrl:     &baseURL,
			ClientId:    &clientID,
			Description: &description,
			Enabled:     &enabled,
		}

		var expectedAPIClientsRep []api.ClientRepresentation
		expectedAPIClientsRep = append(expectedAPIClientsRep, expectedAPIClientRep)

		assert.Nil(t, err)
		assert.Equal(t, expectedAPIClientsRep, apiClientsRep)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetClients(accessToken, realmName).Return([]kc.ClientRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetClients(ctx, "master")

		assert.NotNil(t, err)
	}
}

func TestCreateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var username = "test"
	var realmName = "master"
	var locationURL = "http://toto.com/realms/UUID"

	// Create with minimum properties
	{
		var kcUserRep = kc.UserRepresentation{
			Username: &username,
		}

		mockKeycloakClient.EXPECT().CreateUser(accessToken, realmName, kcUserRep).Return(locationURL, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var userRep = api.UserRepresentation{
			Username: &username,
		}

		location, err := managementComponent.CreateUser(ctx, "master", userRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	}

	// Create with all properties allowed by Brdige API
	{
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var mobilePhone = "+41789456"
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"

		mockKeycloakClient.EXPECT().CreateUser(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) (string, error) {
				assert.Equal(t, username, *kcUserRep.Username)
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, enabled, *kcUserRep.Enabled)
				assert.Equal(t, emailVerified, *kcUserRep.EmailVerified)
				assert.Equal(t, firstName, *kcUserRep.FirstName)
				assert.Equal(t, lastName, *kcUserRep.LastName)
				assert.Equal(t, mobilePhone, (*kcUserRep.Attributes)["mobilephone"][0])
				assert.Equal(t, label, (*kcUserRep.Attributes)["label"][0])
				assert.Equal(t, gender, (*kcUserRep.Attributes)["gender"][0])
				assert.Equal(t, birthDate, (*kcUserRep.Attributes)["birthDate"][0])

				return locationURL, nil
			}).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var userRep = api.UserRepresentation{
			Username:      &username,
			Email:         &email,
			Enabled:       &enabled,
			EmailVerified: &emailVerified,
			FirstName:     &firstName,
			LastName:      &lastName,
			MobilePhone:   &mobilePhone,
			Label:         &label,
			Gender:        &gender,
			BirthDate:     &birthDate,
		}

		location, err := managementComponent.CreateUser(ctx, "master", userRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	}

	// Error from KC client
	{
		var kcUserRep = kc.UserRepresentation{}

		mockKeycloakClient.EXPECT().CreateUser(accessToken, realmName, kcUserRep).Return("", fmt.Errorf("Invalid input")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var userRep = api.UserRepresentation{}

		location, err := managementComponent.CreateUser(ctx, "master", userRep)

		assert.NotNil(t, err)
		assert.Equal(t, "", location)
	}
}

func TestDeleteUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var userID = "1234-7558-7645"
	var realmName = "master"

	// Delete user with success
	{
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		err := managementComponent.DeleteUser(ctx, "master", userID)

		assert.Nil(t, err)
	}

	// Error from KC client
	{
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(fmt.Errorf("Invalid input")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		err := managementComponent.DeleteUser(ctx, "master", userID)

		assert.NotNil(t, err)
	}
}

func TestGetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Get user with succces
	{
		var id = "1234-7454-4516"
		var username = "username"
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var mobilePhone = "+41789456"
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"

		var attributes = make(map[string][]string)
		attributes["mobilephone"] = []string{mobilePhone}
		attributes["label"] = []string{label}
		attributes["gender"] = []string{gender}
		attributes["birthDate"] = []string{birthDate}

		var kcUserRep = kc.UserRepresentation{
			Id:            &id,
			Username:      &username,
			Email:         &email,
			Enabled:       &enabled,
			EmailVerified: &emailVerified,
			FirstName:     &firstName,
			LastName:      &lastName,
			Attributes:    &attributes,
		}

		mockKeycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kcUserRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiUserRep, err := managementComponent.GetUser(ctx, "master", id)

		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, enabled, *apiUserRep.Enabled)
		assert.Equal(t, emailVerified, *apiUserRep.EmailVerified)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, mobilePhone, *apiUserRep.MobilePhone)
		assert.Equal(t, label, *apiUserRep.Label)
		assert.Equal(t, gender, *apiUserRep.Gender)
		assert.Equal(t, birthDate, *apiUserRep.BirthDate)
	}

	//Error
	{
		var id = "1234-79894-7594"
		mockKeycloakClient.EXPECT().GetUser(accessToken, realmName, id).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetUser(ctx, "master", id)

		assert.NotNil(t, err)
	}
}

func TestUpdateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Update user with succces
	{
		var id = "1234-7454-4516"
		var username = "username"
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var mobilePhone = "+41789456"
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"

		var attributes = make(map[string][]string)
		attributes["mobilephone"] = []string{mobilePhone}
		attributes["label"] = []string{label}
		attributes["gender"] = []string{gender}
		attributes["birthDate"] = []string{birthDate}

		mockKeycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, id string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, username, *kcUserRep.Username)
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, enabled, *kcUserRep.Enabled)
				assert.Equal(t, emailVerified, *kcUserRep.EmailVerified)
				assert.Equal(t, firstName, *kcUserRep.FirstName)
				assert.Equal(t, lastName, *kcUserRep.LastName)
				assert.Equal(t, mobilePhone, (*kcUserRep.Attributes)["mobilephone"][0])
				assert.Equal(t, label, (*kcUserRep.Attributes)["label"][0])
				assert.Equal(t, gender, (*kcUserRep.Attributes)["gender"][0])
				assert.Equal(t, birthDate, (*kcUserRep.Attributes)["birthDate"][0])

				return nil
			}).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var userRep = api.UserRepresentation{
			Username:      &username,
			Email:         &email,
			Enabled:       &enabled,
			EmailVerified: &emailVerified,
			FirstName:     &firstName,
			LastName:      &lastName,
			MobilePhone:   &mobilePhone,
			Label:         &label,
			Gender:        &gender,
			BirthDate:     &birthDate,
		}

		err := managementComponent.UpdateUser(ctx, "master", id, userRep)

		assert.Nil(t, err)
	}

	//Error
	{
		var id = "1234-79894-7594"
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, realmName, id, gomock.Any()).Return(fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		err := managementComponent.UpdateUser(ctx, "master", id, api.UserRepresentation{})

		assert.NotNil(t, err)
	}
}

func TestGetUsers(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Get user with succces
	{
		var id = "1234-7454-4516"
		var username = "username"
		var email = "toto@elca.ch"
		var enabled = true
		var emailVerified = true
		var firstName = "Titi"
		var lastName = "Tutu"
		var mobilePhone = "+41789456"
		var label = "Label"
		var gender = "M"
		var birthDate = "01/01/1988"

		var attributes = make(map[string][]string)
		attributes["mobilephone"] = []string{mobilePhone}
		attributes["label"] = []string{label}
		attributes["gender"] = []string{gender}
		attributes["birthDate"] = []string{birthDate}

		var kcUserRep = kc.UserRepresentation{
			Id:            &id,
			Username:      &username,
			Email:         &email,
			Enabled:       &enabled,
			EmailVerified: &emailVerified,
			FirstName:     &firstName,
			LastName:      &lastName,
			Attributes:    &attributes,
		}

		var kcUsersRep []kc.UserRepresentation
		kcUsersRep = append(kcUsersRep, kcUserRep)

		mockKeycloakClient.EXPECT().GetUsers(accessToken, realmName).Return(kcUsersRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiUsersRep, err := managementComponent.GetUsers(ctx, "master", "Support")

		var apiUserRep = apiUsersRep[0]
		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, enabled, *apiUserRep.Enabled)
		assert.Equal(t, emailVerified, *apiUserRep.EmailVerified)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, mobilePhone, *apiUserRep.MobilePhone)
		assert.Equal(t, label, *apiUserRep.Label)
		assert.Equal(t, gender, *apiUserRep.Gender)
		assert.Equal(t, birthDate, *apiUserRep.BirthDate)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetUsers(accessToken, realmName).Return([]kc.UserRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetUsers(ctx, "master", "Support")

		assert.NotNil(t, err)
	}
}

func TestGetClientRolesForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var clientID = "456-789-147"

	// Get role with succces
	{
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "client name"

		var kcRoleRep = kc.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mockKeycloakClient.EXPECT().GetClientRoleMappings(accessToken, realmName, userID, clientID).Return(kcRolesRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiRolesRep, err := managementComponent.GetClientRolesForUser(ctx, "master", userID, clientID)

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.Id)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerId)
		assert.Equal(t, description, *apiRoleRep.Description)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetClientRoleMappings(accessToken, realmName, userID, clientID).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetClientRolesForUser(ctx, "master", userID, clientID)

		assert.NotNil(t, err)
	}
}

func TestAddClientRolesToUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"
	var clientID = "456-789-147"

	// Add role with succces
	{
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "client name"

		var kcRoleRep = kc.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mockKeycloakClient.EXPECT().AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, userID, clientID string, roles []kc.RoleRepresentation) error {
				var role = roles[0]
				assert.Equal(t, id, *role.Id)
				assert.Equal(t, name, *role.Name)
				assert.Equal(t, clientRole, *role.ClientRole)
				assert.Equal(t, composite, *role.Composite)
				assert.Equal(t, containerID, *role.ContainerId)
				assert.Equal(t, description, *role.Description)
				return nil
			}).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var roleRep = api.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}
		var rolesRep []api.RoleRepresentation
		rolesRep = append(rolesRep, roleRep)

		err := managementComponent.AddClientRolesToUser(ctx, "master", userID, clientID, rolesRep)

		assert.Nil(t, err)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, gomock.Any()).Return(fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		err := managementComponent.AddClientRolesToUser(ctx, "master", userID, clientID, []api.RoleRepresentation{})

		assert.NotNil(t, err)
	}
}

func TestGetRealmRolesForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "789-789-456"

	// Get role with succces
	{
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = false
		var name = "client name"

		var kcRoleRep = kc.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mockKeycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return(kcRolesRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiRolesRep, err := managementComponent.GetRealmRolesForUser(ctx, "master", userID)

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.Id)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerId)
		assert.Equal(t, description, *apiRoleRep.Description)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, userID).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetRealmRolesForUser(ctx, "master", userID)

		assert.NotNil(t, err)
	}
}

func TestResetPassword(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "1245-7854-8963"
	var password = "P@ssw0rd"
	var typePassword = "password"

	// Change password
	{
		var kcCredRep = kc.CredentialRepresentation{
			Type:  &typePassword,
			Value: &password,
		}

		mockKeycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, kcCredRep).Return(nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var passwordRep = api.PasswordRepresentation{
			Value: &password,
		}

		err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.Nil(t, err)
	}

	// Error
	{
		mockKeycloakClient.EXPECT().ResetPassword(accessToken, realmName, userID, gomock.Any()).Return(fmt.Errorf("Invalid input")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var passwordRep = api.PasswordRepresentation{
			Value: &password,
		}

		err := managementComponent.ResetPassword(ctx, "master", userID, passwordRep)

		assert.NotNil(t, err)
	}
}

func TestSendVerifyEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var userID = "1245-7854-8963"

	var key1 = "key1"
	var value1 = "value1"
	var key2 = "key2"
	var value2 = "value2"

	// Send email
	{

		mockKeycloakClient.EXPECT().SendVerifyEmail(accessToken, realmName, userID, key1, value1, key2, value2).Return(nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		err := managementComponent.SendVerifyEmail(ctx, "master", userID, key1, value1, key2, value2)

		assert.Nil(t, err)
	}

	// Error
	{
		mockKeycloakClient.EXPECT().SendVerifyEmail(accessToken, realmName, userID).Return(fmt.Errorf("Invalid input")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		err := managementComponent.SendVerifyEmail(ctx, "master", userID)

		assert.NotNil(t, err)
	}
}

func TestGetCredentialsForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)
	var accessToken = "TOKEN=="
	var realmReq = "master"
	var realmName = "otherRealm"
	var userID = "1245-7854-8963"

	// Get credentials for user
	{
		mockKeycloakClient.EXPECT().GetCredentialsForUser(accessToken, realmReq, realmName, userID).Return([]kc.CredentialRepresentation{}, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "realm", realmReq)

		_, err := managementComponent.GetCredentialsForUser(ctx, realmName, userID)

		assert.Nil(t, err)
	}
}

func TestDeleteCredentialsForUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)
	var accessToken = "TOKEN=="
	var realmReq = "master"
	var realmName = "master"
	var userID = "1245-7854-8963"
	var credential = "987-654-321"

	// Get credentials for user
	{
		mockKeycloakClient.EXPECT().DeleteCredentialsForUser(accessToken, realmReq, realmName, userID, credential).Return(nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "realm", realmReq)

		err := managementComponent.DeleteCredentialsForUser(ctx, realmName, userID, credential)

		assert.Nil(t, err)
	}
}

func TestGetRoles(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Get roles with succces
	{
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = false
		var name = "name"

		var kcRoleRep = kc.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mockKeycloakClient.EXPECT().GetRoles(accessToken, realmName).Return(kcRolesRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiRolesRep, err := managementComponent.GetRoles(ctx, "master")

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.Id)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerId)
		assert.Equal(t, description, *apiRoleRep.Description)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetRoles(accessToken, realmName).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetRoles(ctx, "master")

		assert.NotNil(t, err)
	}
}

func TestGetRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"

	// Get roles with succces
	{
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = false
		var name = "name"

		var kcRoleRep = kc.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}

		mockKeycloakClient.EXPECT().GetRole(accessToken, realmName, id).Return(kcRoleRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiRoleRep, err := managementComponent.GetRole(ctx, "master", id)

		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.Id)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerId)
		assert.Equal(t, description, *apiRoleRep.Description)
	}

	//Error
	{
		var id = "1234-7454-4516"
		mockKeycloakClient.EXPECT().GetRole(accessToken, realmName, id).Return(kc.RoleRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetRole(ctx, "master", id)

		assert.NotNil(t, err)
	}
}

func TestGetClientRoles(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var clientID = "15436-464-4"

	// Get roles with succces
	{
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "name"

		var kcRoleRep = kc.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}

		var kcRolesRep []kc.RoleRepresentation
		kcRolesRep = append(kcRolesRep, kcRoleRep)

		mockKeycloakClient.EXPECT().GetClientRoles(accessToken, realmName, clientID).Return(kcRolesRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		apiRolesRep, err := managementComponent.GetClientRoles(ctx, "master", clientID)

		var apiRoleRep = apiRolesRep[0]
		assert.Nil(t, err)
		assert.Equal(t, id, *apiRoleRep.Id)
		assert.Equal(t, name, *apiRoleRep.Name)
		assert.Equal(t, clientRole, *apiRoleRep.ClientRole)
		assert.Equal(t, composite, *apiRoleRep.Composite)
		assert.Equal(t, containerID, *apiRoleRep.ContainerId)
		assert.Equal(t, description, *apiRoleRep.Description)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetClientRoles(accessToken, realmName, clientID).Return([]kc.RoleRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.GetClientRoles(ctx, "master", clientID)

		assert.NotNil(t, err)
	}
}

func TestCreateClientRole(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var managementComponent = NewComponent(mockKeycloakClient)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var clientID = "456-789-147"

	// Add role with succces
	{
		var id = "1234-7454-4516"
		var composite = false
		var containerID = "containerId"
		var description = "description role"
		var clientRole = true
		var name = "client name"

		var locationURL = "http://location.url"

		mockKeycloakClient.EXPECT().CreateClientRole(accessToken, realmName, clientID, gomock.Any()).DoAndReturn(
			func(accessToken, realmName, clientID string, role kc.RoleRepresentation) (string, error) {
				assert.Equal(t, id, *role.Id)
				assert.Equal(t, name, *role.Name)
				assert.Equal(t, clientRole, *role.ClientRole)
				assert.Equal(t, composite, *role.Composite)
				assert.Equal(t, containerID, *role.ContainerId)
				assert.Equal(t, description, *role.Description)
				return locationURL, nil
			}).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		var roleRep = api.RoleRepresentation{
			Id:          &id,
			Name:        &name,
			ClientRole:  &clientRole,
			Composite:   &composite,
			ContainerId: &containerID,
			Description: &description,
		}

		location, err := managementComponent.CreateClientRole(ctx, "master", clientID, roleRep)

		assert.Nil(t, err)
		assert.Equal(t, locationURL, location)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().CreateClientRole(accessToken, realmName, clientID, gomock.Any()).Return("", fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)

		_, err := managementComponent.CreateClientRole(ctx, "master", clientID, api.RoleRepresentation{})

		assert.NotNil(t, err)
	}
}
