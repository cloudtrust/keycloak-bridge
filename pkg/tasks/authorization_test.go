package tasks

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	"github.com/cloudtrust/keycloak-bridge/pkg/tasks/mock"
	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockTasksComponent = mock.NewComponent(mockCtrl)
	var mockSecKeycloakClient = mock.NewKcClientAuth(mockCtrl)

	var accessToken = "TOKEN=="
	var toe = "toe"
	var groups = []string{toe}
	var realmName = "dummy"
	var any = "*"

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

	// DENY authorization tests
	t.Run("Deny", func(t *testing.T) {
		var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)
		mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return([]configuration.Authorization{}, nil)

		var authorizations, _ = security.NewAuthorizationManager(mockAuthorizationDBReader, mockSecKeycloakClient, mockLogger)
		var authorizationMW = MakeAuthorizationTasksComponentMW(mockLogger, authorizations)(mockTasksComponent)

		t.Run("DeleteUsersWithExpiredTermsOfUseAcceptance", func(t *testing.T) {
			var err = authorizationMW.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
			assert.Equal(t, security.ForbiddenError{}, err)
		})
	})

	// ALLOW authorization tests
	t.Run("Allow", func(t *testing.T) {
		var allowAuthz = []configuration.Authorization{}
		for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.TaskAPI) {
			var action = string(action.Name)
			allowAuthz = append(allowAuthz, configuration.Authorization{
				RealmID:         &realmName,
				GroupName:       &toe,
				Action:          &action,
				TargetRealmID:   &any,
				TargetGroupName: &any,
			})
		}
		var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)
		mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(allowAuthz, nil)

		var authorizations, _ = security.NewAuthorizationManager(mockAuthorizationDBReader, mockSecKeycloakClient, mockLogger)
		var authorizationMW = MakeAuthorizationTasksComponentMW(mockLogger, authorizations)(mockTasksComponent)

		t.Run("Delete", func(t *testing.T) {
			mockTasksComponent.EXPECT().CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx).Return(nil)
			var err = authorizationMW.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
			assert.Nil(t, err)
		})
	})
}
