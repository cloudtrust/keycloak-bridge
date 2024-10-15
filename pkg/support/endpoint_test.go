package support

import (
	"context"
	"net/http"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/support"
	"github.com/cloudtrust/keycloak-bridge/pkg/support/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMakeGetSupportInformationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockSupportComponent := mock.NewComponent(mockCtrl)
	endpoint := MakeGetSupportInformationEndpoint(mockSupportComponent)

	email := "name@domain.ch"
	ctx := context.TODO()
	request := map[string]string{}

	t.Run("Error", func(t *testing.T) {
		_, err := endpoint(ctx, request)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
	})
	t.Run("Success", func(t *testing.T) {
		request[prmQryEmail] = email
		mockSupportComponent.EXPECT().GetSupportInformation(gomock.Any(), email).Return([]api.EmailInfo{}, nil)
		res, err := endpoint(ctx, request)
		assert.Nil(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res, 0)
	})
}
