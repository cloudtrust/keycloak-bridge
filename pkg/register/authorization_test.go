package register

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	logger "github.com/cloudtrust/common-service/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

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
		mockResponseWriter.EXPECT().WriteHeader(http.StatusForbidden).Times(1)
		mockResponseWriter.EXPECT().Header().Return(req.Header).Times(1)
		mockResponseWriter.EXPECT().Write(gomock.Any()).Times(1)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Not a valid token", func(t *testing.T) {
		req.Header.Set("Authorization", "Don't match regexp")
		mockResponseWriter.EXPECT().WriteHeader(http.StatusForbidden).Times(1)
		mockResponseWriter.EXPECT().Header().Return(req.Header).Times(1)
		mockResponseWriter.EXPECT().Write(gomock.Any()).Times(1)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Recaptcha bad HTTP status", func(t *testing.T) {
		req.Header.Set("Authorization", recaptchaSecret)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(400)
		}).Times(1)
		mockResponseWriter.EXPECT().WriteHeader(http.StatusForbidden).Times(1)
		mockResponseWriter.EXPECT().Header().Return(req.Header).Times(1)
		mockResponseWriter.EXPECT().Write(gomock.Any()).Times(1)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Invalid recaptcha code", func(t *testing.T) {
		req.Header.Set("Authorization", recaptchaSecret)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"success":false}`))
		}).Times(1)
		mockResponseWriter.EXPECT().WriteHeader(403).Times(1)
		mockResponseWriter.EXPECT().Header().Return(req.Header).Times(1)
		mockResponseWriter.EXPECT().Write(gomock.Any()).Times(1)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Recaptcha code is valid", func(t *testing.T) {
		req.Header.Set("Authorization", recaptchaSecret)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"success":true}`))
		}).Times(1)
		mockHTTPHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Times(1)
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})
}

func TestMakeAuthorizationRegisterComponentMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)
	var component = MakeAuthorizationRegisterComponentMW(logger.NewNopLogger())(mockComponent)

	var ctx = context.TODO()
	var realm = "master"
	var user = apiregister.User{}
	var expectedErr = errors.New("")

	mockComponent.EXPECT().RegisterUser(ctx, realm, user).Return("", expectedErr).Times(1)
	var _, err = component.RegisterUser(ctx, realm, user)
	assert.Equal(t, expectedErr, err)

	mockComponent.EXPECT().GetConfiguration(ctx, realm).Return(apiregister.Configuration{}, expectedErr).Times(1)
	_, err = component.GetConfiguration(ctx, realm)
	assert.Equal(t, expectedErr, err)
}
