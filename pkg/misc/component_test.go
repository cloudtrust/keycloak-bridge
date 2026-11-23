package misc

import (
	"context"
	"errors"
	"net/http"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func TestGetSupportInformation(t *testing.T) {
	var mocks = newMiscMocks(t)
	defer mocks.finish()

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

func TestCircuitBreaker(t *testing.T) {
	var mocks = newMiscMocks(t)
	defer mocks.finish()

	var component = mocks.createComponent()

	var realm = "circuitb"
	var accessToken = "acc-ess-to-ken"
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.TODO(), cs.CtContextAccessToken, accessToken)

	t.Run("GetCircuitBreakerStatus", func(t *testing.T) {
		t.Run("Error", func(t *testing.T) {
			mocks.kcClient.EXPECT().GetCircuitBreakerStatus(accessToken, realm).Return(kc.CircuitBreakerRepresentation{}, anyError)
			_, err := component.GetCircuitBreakerStatus(ctx, realm)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			cbr := kc.CircuitBreakerRepresentation{
				Status: new("status"),
			}
			mocks.kcClient.EXPECT().GetCircuitBreakerStatus(accessToken, realm).Return(cbr, nil)
			res, err := component.GetCircuitBreakerStatus(ctx, realm)
			assert.Nil(t, err)
			assert.NotNil(t, res)
			assert.NotNil(t, res.Status, cbr.Status)
		})
	})

	t.Run("OpenCircuitBreaker", func(t *testing.T) {
		t.Run("Error", func(t *testing.T) {
			mocks.kcClient.EXPECT().OpenCircuitBreaker(accessToken, realm).Return(anyError)
			err := component.OpenCircuitBreaker(ctx, realm)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			mocks.kcClient.EXPECT().OpenCircuitBreaker(accessToken, realm).Return(nil)
			err := component.OpenCircuitBreaker(ctx, realm)
			assert.Nil(t, err)
		})
	})

	t.Run("CloseCircuitBreaker", func(t *testing.T) {
		t.Run("Error", func(t *testing.T) {
			mocks.kcClient.EXPECT().CloseCircuitBreaker(accessToken, realm).Return(anyError)
			err := component.CloseCircuitBreaker(ctx, realm)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			mocks.kcClient.EXPECT().CloseCircuitBreaker(accessToken, realm).Return(nil)
			err := component.CloseCircuitBreaker(ctx, realm)
			assert.Nil(t, err)
		})
	})
}
