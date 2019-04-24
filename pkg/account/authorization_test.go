package account

//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/internal/security KeycloakClient

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/security"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	WithoutAuthorization = `{}`
	WithAuthorization    = `{
		"master": {
			"sample-group": {
				"AC_UpdatePassword": {"*": {"*": {} }}
			}
		}
	}`
)

func testAuthorization(t *testing.T, jsonAuthz string, tester func(AccountComponent, *mock.AccountComponent, context.Context, map[string]string)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := mock.NewKeycloakClient(mockCtrl)
	var authorizations, err = security.NewAuthorizationManager(mockKeycloakClient, jsonAuthz)
	assert.Nil(t, err)

	mockLogger := mock.NewLogger(mockCtrl)
	mockAccountComponent := mock.NewAccountComponent(mockCtrl)

	var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockAccountComponent)

	var accessToken = "TOKEN=="
	var groups = []string{"sample-group"}
	var realmName = "master"
	var userID = "123-456-789"
	var groupID = "123-789-454"
	var groupName = "titi"

	var ctx = context.WithValue(context.Background(), "access_token", accessToken)
	ctx = context.WithValue(ctx, "groups", groups)
	ctx = context.WithValue(ctx, "realm", realmName)
	ctx = context.WithValue(ctx, "userId", userID)
	var group = kc.GroupRepresentation{
		Id:   &groupID,
		Name: &groupName,
	}

	mp := make(map[string]string)
	mp["realm"] = realmName
	mp["userID"] = userID

	mockKeycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return([]kc.GroupRepresentation{group}, nil).AnyTimes()

	tester(authorizationMW, mockAccountComponent, ctx, mp)
}

func TestUpdatePasswordAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth AccountComponent, mockComponent *mock.AccountComponent, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().UpdatePassword(ctx, "", "", "").Return(nil).Times(1)
		assert.Nil(t, auth.UpdatePassword(ctx, "", "", ""))
	})
}

func TestUpdatePasswordDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth AccountComponent, mockComponent *mock.AccountComponent, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().UpdatePassword(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(0)
		assert.Equal(t, security.ForbiddenError{}, auth.UpdatePassword(ctx, "", "", ""))
	})
}
