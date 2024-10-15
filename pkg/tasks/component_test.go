package tasks

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/pkg/tasks/mock"
	"github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	kcClient       *mock.KeycloakClient
	eventsReporter *mock.AuditEventsReporterModule
	logger         log.Logger
}

func newMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		kcClient:       mock.NewKeycloakClient(mockCtrl),
		eventsReporter: mock.NewAuditEventsReporterModule(mockCtrl),
		logger:         log.NewNopLogger(),
	}
}

func (m *componentMocks) createComponent() Component {
	return NewComponent(m.kcClient, m.eventsReporter, m.logger)
}

func TestCleanUpAccordingToExpiredTermsOfUseAcceptance(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := newMocks(mockCtrl)
	component := mocks.createComponent()

	accessToken := "acc-ess-to-ken"
	anyError := errors.New("any error")
	ctx := context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	t.Run("Retrieve details from Keycloak fails", func(t *testing.T) {
		mocks.kcClient.EXPECT().GetExpiredTermsOfUseAcceptance(accessToken).Return(nil, anyError)
		err := component.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
		assert.Equal(t, anyError, err)
	})
	t.Run("No eligible user", func(t *testing.T) {
		mocks.kcClient.EXPECT().GetExpiredTermsOfUseAcceptance(accessToken).Return(nil, nil)
		err := component.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
		assert.Nil(t, err)
	})
	t.Run("Two eligible users, first is failing", func(t *testing.T) {
		eligibleUsers := []keycloak.DeletableUserRepresentation{
			{RealmID: "realm-id-1", RealmName: "realm-name-1", UserID: "user-id-1", Username: "user-id-1"},
			{RealmID: "realm-id-2", RealmName: "realm-name-2", UserID: "user-id-2", Username: "user-id-2"},
		}
		mocks.kcClient.EXPECT().GetExpiredTermsOfUseAcceptance(accessToken).Return(eligibleUsers, nil)
		mocks.kcClient.EXPECT().DeleteUser(accessToken, eligibleUsers[0].RealmName, eligibleUsers[0].UserID).Return(anyError)
		mocks.kcClient.EXPECT().DeleteUser(accessToken, eligibleUsers[1].RealmName, eligibleUsers[1].UserID).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		err := component.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
		assert.Equal(t, anyError, err)
	})
	t.Run("Three eligible users, second and third are failing", func(t *testing.T) {
		eligibleUsers := []keycloak.DeletableUserRepresentation{
			{RealmID: "realm-id-1", RealmName: "realm-name-1", UserID: "user-id-1", Username: "user-id-1"},
			{RealmID: "realm-id-2", RealmName: "realm-name-2", UserID: "user-id-2", Username: "user-id-2"},
			{RealmID: "realm-id-3", RealmName: "realm-name-3", UserID: "user-id-3", Username: "user-id-3"},
		}
		altError := errors.New("Does not match this one")
		mocks.kcClient.EXPECT().GetExpiredTermsOfUseAcceptance(accessToken).Return(eligibleUsers, nil)
		// User 1
		mocks.kcClient.EXPECT().DeleteUser(accessToken, eligibleUsers[0].RealmName, eligibleUsers[0].UserID).Return(nil)
		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())
		// User 2
		mocks.kcClient.EXPECT().DeleteUser(accessToken, eligibleUsers[1].RealmName, eligibleUsers[1].UserID).Return(altError)
		// User 3
		mocks.kcClient.EXPECT().DeleteUser(accessToken, eligibleUsers[2].RealmName, eligibleUsers[2].UserID).Return(anyError)

		err := component.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
		assert.Equal(t, anyError, err)
	})
}
