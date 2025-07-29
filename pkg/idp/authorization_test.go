package idp

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	"github.com/cloudtrust/keycloak-bridge/pkg/idp/mock"
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
	var mockIdpComponent = mock.NewComponent(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var groupID = "123-789-454"
	var groupName = "titi"

	var idpAlias = "trustid-idp"
	var idpDisplayName = "MyTrustID"

	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return([]configuration.Authorization{}, nil)

	var idp = api.IdentityProviderRepresentation{
		Alias:       &idpAlias,
		DisplayName: &idpDisplayName,
	}

	// Nothing allowed
	{
		var authorizations, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, log.NewNopLogger())
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationIdpComponentMW(mockLogger, authorizations)(mockIdpComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).AnyTimes()

		var tests = map[string]error{
			"GetIdentityProvider":    ignoreFirst(authorizationMW.GetIdentityProvider(ctx, realmName, idpAlias)),
			"CreateIdentityProvider": authorizationMW.CreateIdentityProvider(ctx, realmName, idp),
			"UpdateIdentityProvider": authorizationMW.UpdateIdentityProvider(ctx, realmName, idpAlias, idp),
			"DeleteIdentityProvider": authorizationMW.DeleteIdentityProvider(ctx, realmName, idpAlias),
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
	var mockIdpComponent = mock.NewComponent(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"

	var toe = "toe"
	var any = "*"

	var groupName = "titi"

	var idpAlias = "trustid-idp"

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(gomock.Any(), accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	var idp = api.IdentityProviderRepresentation{}

	var authorizations = []configuration.Authorization{}
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.IdpAPI) {
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

		var authorizationMW = MakeAuthorizationIdpComponentMW(mockLogger, authorizationManager)(mockIdpComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		mockIdpComponent.EXPECT().GetIdentityProvider(ctx, realmName, idpAlias).Return(idp, nil)
		_, err = authorizationMW.GetIdentityProvider(ctx, realmName, idpAlias)
		assert.Nil(t, err)

		mockIdpComponent.EXPECT().CreateIdentityProvider(ctx, realmName, idp).Return(nil)
		err = authorizationMW.CreateIdentityProvider(ctx, realmName, idp)
		assert.Nil(t, err)

		mockIdpComponent.EXPECT().UpdateIdentityProvider(ctx, realmName, idpAlias, idp).Return(nil)
		err = authorizationMW.UpdateIdentityProvider(ctx, realmName, idpAlias, idp)
		assert.Nil(t, err)

		mockIdpComponent.EXPECT().DeleteIdentityProvider(ctx, realmName, idpAlias).Return(nil)
		err = authorizationMW.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.Nil(t, err)
	}
}
