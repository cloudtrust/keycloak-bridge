package register

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	logger "github.com/cloudtrust/common-service/v2/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func configureMock(mockResponse *mock.ResponseWriter, statusCode int, header http.Header) {
	mockResponse.EXPECT().WriteHeader(statusCode)
	mockResponse.EXPECT().Header().Return(header)
	mockResponse.EXPECT().Write(gomock.Any())
}

func TestMakeHTTPRecaptchaValidationMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockHTTPHandler = mock.NewHandler(mockCtrl)
	var mockRecaptchaHandler = mock.NewHandler(mockCtrl)
	var mockResponseWriter = mock.NewResponseWriter(mockCtrl)

	var recaptchaPath = "/recaptcha"
	var recaptchaSecret = "thesecretfortherecaptchaverifyprocess"
	r := mux.NewRouter()
	r.Handle(recaptchaPath, mockRecaptchaHandler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var authHandler = MakeHTTPRecaptchaValidationMW(ts.URL+recaptchaPath, recaptchaSecret, logger.NewNopLogger())(mockHTTPHandler)

	var req = http.Request{
		Header: make(http.Header),
	}

	t.Run("Missing authentication", func(t *testing.T) {
		configureMock(mockResponseWriter, http.StatusForbidden, req.Header)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Not a valid token", func(t *testing.T) {
		req.Header.Set("Authorization", "Don't match regexp")
		configureMock(mockResponseWriter, http.StatusForbidden, req.Header)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Recaptcha bad HTTP status", func(t *testing.T) {
		req.Header.Set("Authorization", recaptchaSecret)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(400)
		})
		configureMock(mockResponseWriter, http.StatusForbidden, req.Header)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Can't deserialize captcha response", func(t *testing.T) {
		req.Header.Set("Authorization", recaptchaSecret)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"success":f`))
		})
		configureMock(mockResponseWriter, http.StatusForbidden, req.Header)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Invalid recaptcha code", func(t *testing.T) {
		req.Header.Set("Authorization", recaptchaSecret)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"success":false}`))
		})
		configureMock(mockResponseWriter, http.StatusForbidden, req.Header)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Recaptcha code is valid", func(t *testing.T) {
		req.Header.Set("Authorization", recaptchaSecret)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"success":true}`))
		})
		mockHTTPHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any())
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})
}

func TestMakeAuthorizationRegisterComponentMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)
	var component = MakeAuthorizationRegisterComponentMW(logger.NewNopLogger())(mockComponent)

	var ctx = context.TODO()
	var socialRealm = "social"
	var realm = "my-realm"
	var user = apiregister.UserRepresentation{}
	var expectedErr = errors.New("")

	mockComponent.EXPECT().RegisterUser(ctx, socialRealm, realm, user, nil).Return("", expectedErr)
	_, err := component.RegisterUser(ctx, socialRealm, realm, user, nil)
	assert.Equal(t, expectedErr, err)

	mockComponent.EXPECT().GetConfiguration(ctx, realm).Return(apiregister.ConfigurationRepresentation{}, expectedErr)
	_, err = component.GetConfiguration(ctx, realm)
	assert.Equal(t, expectedErr, err)
}
