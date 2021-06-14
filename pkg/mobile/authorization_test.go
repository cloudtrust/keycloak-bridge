package mobilepkg

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/mobile"

	"github.com/cloudtrust/keycloak-bridge/pkg/mobile/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNoRestrictions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockMobileComponent = mock.NewComponent(mockCtrl)

	var ctx = context.TODO()

	t.Run("GetUserInformation", func(t *testing.T) {
		var authorizationMW = MakeAuthorizationMobileComponentMW(mockLogger)(mockMobileComponent)
		mockMobileComponent.EXPECT().GetUserInformation(ctx).Return(api.UserInformationRepresentation{}, nil)
		_, err := authorizationMW.GetUserInformation(ctx)
		assert.Nil(t, err)
	})
}
