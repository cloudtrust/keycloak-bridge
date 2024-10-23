package support

import (
	"context"
	"net/http"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/support"
	"github.com/cloudtrust/keycloak-bridge/pkg/support/mock"
	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeGetSupportInformationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockSupportComponent = mock.NewComponent(mockCtrl)
	var endpoint = MakeGetSupportInformationEndpoint(mockSupportComponent)

	var email = "name@domain.ch"
	var ctx = context.TODO()
	var request = map[string]string{}

	t.Run("Error", func(t *testing.T) {
		var _, err = endpoint(ctx, request)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
	})
	t.Run("Success", func(t *testing.T) {
		request[prmQryEmail] = email
		mockSupportComponent.EXPECT().GetSupportInformation(gomock.Any(), email).Return([]api.EmailInfo{}, nil)
		var res, err = endpoint(ctx, request)
		assert.Nil(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res, 0)
	})
}
