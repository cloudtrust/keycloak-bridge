package tasks

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	"github.com/cloudtrust/keycloak-bridge/pkg/tasks/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuthorizations(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockLogger := log.NewNopLogger()
	mockTasksComponent := mock.NewComponent(mockCtrl)
	mockSecKeycloakClient := mock.NewKcClientAuth(mockCtrl)

	accessToken := "TOKEN=="
	toe := "toe"
	groups := []string{toe}
	realmName := "dummy"
	any := "*"

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

	// DENY authorization tests
	t.Run("Deny", func(t *testing.T) {
		mockAuthorizationDBReader := mock.NewAuthorizationDBReader(mockCtrl)
		mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return([]configuration.Authorization{}, nil)

		authorizations, _ := security.NewAuthorizationManager(mockAuthorizationDBReader, mockSecKeycloakClient, mockLogger)
		authorizationMW := MakeAuthorizationTasksComponentMW(mockLogger, authorizations)(mockTasksComponent)

		t.Run("DeleteUsersWithExpiredTermsOfUseAcceptance", func(t *testing.T) {
			err := authorizationMW.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
			assert.Equal(t, security.ForbiddenError{}, err)
		})
	})

	// ALLOW authorization tests
	t.Run("Allow", func(t *testing.T) {
		allowAuthz := []configuration.Authorization{}
		for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.TaskAPI) {
			action := string(action.Name)
			allowAuthz = append(allowAuthz, configuration.Authorization{
				RealmID:         &realmName,
				GroupName:       &toe,
				Action:          &action,
				TargetRealmID:   &any,
				TargetGroupName: &any,
			})
		}
		mockAuthorizationDBReader := mock.NewAuthorizationDBReader(mockCtrl)
		mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(allowAuthz, nil)

		authorizations, _ := security.NewAuthorizationManager(mockAuthorizationDBReader, mockSecKeycloakClient, mockLogger)
		authorizationMW := MakeAuthorizationTasksComponentMW(mockLogger, authorizations)(mockTasksComponent)

		t.Run("Delete", func(t *testing.T) {
			mockTasksComponent.EXPECT().CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx).Return(nil)
			err := authorizationMW.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
			assert.Nil(t, err)
		})
	})
}
