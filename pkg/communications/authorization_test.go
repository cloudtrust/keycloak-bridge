package communications

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications/mock"
	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestDeny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockCommunicationsComponent = mock.NewComponent(mockCtrl)
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)

	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)
	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return([]configuration.Authorization{}, nil)

	var accessToken = "TOKEN=="
	var groups = []string{"toe"}
	var realmName = "realm"
	var userID = "testerID"

	{
		var authorizations, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationCommunicationsComponentMW(mockLogger, authorizations)(mockCommunicationsComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		err = authorizationMW.SendEmail(ctx, realmName, emailForTest)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.SendEmailToUser(ctx, realmName, userID, emailForTest)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.SendSMS(ctx, realmName, smsForTest)
		assert.Equal(t, security.ForbiddenError{}, err)
	}
}

func TestAllow(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockCommunicationsComponent = mock.NewComponent(mockCtrl)
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)

	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

	var accessToken = "TOKEN=="
	var groups = []string{"toe"}
	var realmName = "master"
	var toe = "toe"
	var any = "*"
	var userID = "testerID"

	var authorizations = []configuration.Authorization{}
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.CommunicationAPI) {
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

	{
		var authorizationManager, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationCommunicationsComponentMW(mockLogger, authorizationManager)(mockCommunicationsComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		mockCommunicationsComponent.EXPECT().SendEmail(ctx, realmName, emailForTest).Return(nil).Times(1)
		err = authorizationMW.SendEmail(ctx, realmName, emailForTest)
		assert.Nil(t, err)

		mockCommunicationsComponent.EXPECT().SendEmailToUser(ctx, realmName, userID, emailForTest).Return(nil).Times(1)
		err = authorizationMW.SendEmailToUser(ctx, realmName, userID, emailForTest)
		assert.Nil(t, err)

		mockCommunicationsComponent.EXPECT().SendSMS(ctx, realmName, smsForTest).Return(nil).Times(1)
		err = authorizationMW.SendSMS(ctx, realmName, smsForTest)
		assert.Nil(t, err)
	}
}
