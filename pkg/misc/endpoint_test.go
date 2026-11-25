package misc

import (
	"context"
	"errors"
	"net/http"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/misc"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMiscEndpoints(t *testing.T) {
	mocks := newMiscMocks(t)
	defer mocks.finish()

	endpoints := mocks.newEndpoints()

	var ctx = context.TODO()
	var realm = "circuitbreaker"
	var request = map[string]string{
		prmRealm: realm,
	}
	var dummyError = errors.New("dummy")

	t.Run("MakeGetSupportInformation", func(t *testing.T) {
		var email = "name@domain.ch"
		t.Run("Error", func(t *testing.T) {
			var _, err = endpoints.GetSupportInformation(ctx, request)
			assert.NotNil(t, err)
			assert.IsType(t, errorhandler.Error{}, err)
			assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
		})
		t.Run("Success", func(t *testing.T) {
			request[prmQryEmail] = email
			mocks.component.EXPECT().GetSupportInformation(gomock.Any(), email).Return([]api.EmailInfo{}, nil)
			var res, err = endpoints.GetSupportInformation(ctx, request)
			assert.Nil(t, err)
			assert.NotNil(t, res)
			assert.Len(t, res, 0)
		})
	})

	t.Run("MakeGetCircuitBreakerStatusEndpoint", func(t *testing.T) {
		status := api.CircuitBreakerStatus{}
		mocks.component.EXPECT().GetCircuitBreakerStatus(gomock.Any(), realm).Return(status, nil)
		res, err := endpoints.GetCircuitBreakerStatus(ctx, request)
		assert.Nil(t, err)
		assert.Equal(t, status, res)
	})

	t.Run("MakeOpenCircuitBreakerEndpoint", func(t *testing.T) {
		mocks.component.EXPECT().OpenCircuitBreaker(gomock.Any(), realm).Return(dummyError)
		_, err := endpoints.OpenCircuitBreaker(ctx, request)
		assert.NotNil(t, err)
	})

	t.Run("MakeCloseCircuitBreakerEndpoint", func(t *testing.T) {
		mocks.component.EXPECT().CloseCircuitBreaker(gomock.Any(), realm).Return(dummyError)
		_, err := endpoints.CloseCircuitBreaker(ctx, request)
		assert.NotNil(t, err)
	})
}
