package mobilepkg

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/mobile"

	"github.com/cloudtrust/keycloak-bridge/pkg/mobile/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNoRestrictions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockLogger := log.NewNopLogger()
	mockMobileComponent := mock.NewComponent(mockCtrl)

	ctx := context.TODO()

	t.Run("GetUserInformation", func(t *testing.T) {
		authorizationMW := MakeAuthorizationMobileComponentMW(mockLogger)(mockMobileComponent)
		mockMobileComponent.EXPECT().GetUserInformation(ctx).Return(api.UserInformationRepresentation{}, nil)
		_, err := authorizationMW.GetUserInformation(ctx)
		assert.Nil(t, err)
	})
}
