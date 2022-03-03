package support

import (
	"context"
	"errors"
	"net/http"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/pkg/support/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	kcClient *mock.KeycloakClient
	logger   log.Logger
}

func newMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		kcClient: mock.NewKeycloakClient(mockCtrl),
		logger:   log.NewNopLogger(),
	}
}

func (m *componentMocks) createComponent() Component {
	return NewComponent(m.kcClient, m.logger)
}

func TestGetSupportInformation(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newMocks(mockCtrl)
	var component = mocks.createComponent()

	var accessToken = "acc-ess-to-ken"
	var email = "name@domain.net"
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	t.Run("Keycloak call fails", func(t *testing.T) {
		mocks.kcClient.EXPECT().GetSupportInfo(accessToken, email).Return(nil, anyError)
		var _, err = component.GetSupportInformation(ctx, email)
		assert.Equal(t, anyError, err)
	})
	t.Run("email not found in Keycloak", func(t *testing.T) {
		mocks.kcClient.EXPECT().GetSupportInfo(accessToken, email).Return(nil, kc.HTTPError{HTTPStatus: http.StatusNotFound})
		var _, err = component.GetSupportInformation(ctx, email)
		assert.NotNil(t, err)
		assert.IsType(t, errorhandler.Error{}, err)
		assert.Equal(t, http.StatusNotFound, err.(errorhandler.Error).Status)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.kcClient.EXPECT().GetSupportInfo(accessToken, email).Return([]kc.EmailInfoRepresentation{{}, {}}, nil)
		var res, err = component.GetSupportInformation(ctx, email)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})
}
