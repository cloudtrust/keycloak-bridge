package components

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/components"
	"github.com/cloudtrust/keycloak-bridge/pkg/components/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func ignoreFirst(_ interface{}, err error) error {
	return err
}

func TestDeny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)
	var mockCompComponent = mock.NewComponent(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var groupID = "123-789-454"
	var groupName = "titi"

	var compID = "b5fd6854-ac8e-415b-8779-d89e6b6de3f4"
	var compName = "MyTrustID"
	var providerType = "org.keycloak.services.ui.extend.UiTabProvider"

	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return([]configuration.Authorization{}, nil)

	var comp = api.ComponentRepresentation{
		ID:   &compID,
		Name: &compName,
	}

	// Nothing allowed
	{
		var authorizations, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, log.NewNopLogger())
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationCompComponentMW(mockLogger, authorizations)(mockCompComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).AnyTimes()

		var tests = map[string]error{
			"GetComponents":   ignoreFirst(authorizationMW.GetComponents(ctx, realmName, &providerType)),
			"CreateComponent": authorizationMW.CreateComponent(ctx, realmName, comp),
			"UpdateComponent": authorizationMW.UpdateComponent(ctx, realmName, compID, comp),
		}
		for testName, testResult := range tests {
			t.Run(testName, func(t *testing.T) {
				assert.Equal(t, security.ForbiddenError{}, testResult)
			})
		}
	}
}

func TestAllowed(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)
	var mockCompComponent = mock.NewComponent(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"

	var toe = "toe"
	var any = "*"

	var groupName = "titi"

	var compID = "trustid-idp"
	var providerType = "org.keycloak.services.ui.extend.UiTabProvider"

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(gomock.Any(), accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	var comp = api.ComponentRepresentation{}

	var authorizations = []configuration.Authorization{}
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.ComponentsAPI) {
		var action = string(action.Name)
		authorizations = append(authorizations, configuration.Authorization{
			RealmID:         &realmName,
			GroupName:       &toe,
			Action:          &action,
			TargetRealmID:   &any,
			TargetGroupName: &any,
		})
	}
	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(authorizations, nil)

	// Anything allowed
	{
		var authorizationManager, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, log.NewNopLogger())
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationCompComponentMW(mockLogger, authorizationManager)(mockCompComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		mockCompComponent.EXPECT().GetComponents(ctx, realmName, &providerType).Return([]api.ComponentRepresentation{comp}, nil)
		_, err = authorizationMW.GetComponents(ctx, realmName, &providerType)
		assert.Nil(t, err)

		mockCompComponent.EXPECT().CreateComponent(ctx, realmName, comp).Return(nil)
		err = authorizationMW.CreateComponent(ctx, realmName, comp)
		assert.Nil(t, err)

		mockCompComponent.EXPECT().UpdateComponent(ctx, realmName, compID, comp).Return(nil)
		err = authorizationMW.UpdateComponent(ctx, realmName, compID, comp)
		assert.Nil(t, err)
	}
}
