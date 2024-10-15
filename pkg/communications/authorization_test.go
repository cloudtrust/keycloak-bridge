package communications

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestDeny(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockLogger := log.NewNopLogger()
	mockCommunicationsComponent := mock.NewComponent(mockCtrl)
	mockKeycloakClient := mock.NewKcClientAuth(mockCtrl)

	mockAuthorizationDBReader := mock.NewAuthorizationDBReader(mockCtrl)
	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return([]configuration.Authorization{}, nil)

	accessToken := "TOKEN=="
	groups := []string{"toe"}
	realmName := "realm"
	userID := "testerID"

	{
		authorizations, err := security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
		assert.Nil(t, err)

		authorizationMW := MakeAuthorizationCommunicationsComponentMW(mockLogger, authorizations)(mockCommunicationsComponent)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockLogger := log.NewNopLogger()
	mockCommunicationsComponent := mock.NewComponent(mockCtrl)
	mockKeycloakClient := mock.NewKcClientAuth(mockCtrl)

	mockAuthorizationDBReader := mock.NewAuthorizationDBReader(mockCtrl)

	accessToken := "TOKEN=="
	groups := []string{"toe"}
	realmName := "master"
	toe := "toe"
	any := "*"
	userID := "testerID"

	authorizations := []configuration.Authorization{}
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.CommunicationAPI) {
		action := string(action.Name)
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
		authorizationManager, err := security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
		assert.Nil(t, err)

		authorizationMW := MakeAuthorizationCommunicationsComponentMW(mockLogger, authorizationManager)(mockCommunicationsComponent)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
