package mobilepkg

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/mobile"
	"github.com/cloudtrust/keycloak-bridge/pkg/mobile/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeGetUserInformationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockMobileComponent := mock.NewComponent(mockCtrl)
	m := map[string]string{}

	mockMobileComponent.EXPECT().GetUserInformation(gomock.Any()).Return(api.UserInformationRepresentation{}, nil)
	_, err := MakeGetUserInformationEndpoint(mockMobileComponent)(context.Background(), m)
	assert.Nil(t, err)
}
