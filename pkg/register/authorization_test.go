package register

import (
	"context"
	"encoding/base64"
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
	r := mux.NewRouter()
	r.Handle(recaptchaPath, mockRecaptchaHandler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var authHandler = MakeHTTPRecaptchaValidationMW(ts.URL+recaptchaPath, logger.NewNopLogger())(mockHTTPHandler)
	var req = http.Request{
		Header: make(http.Header),
	}

	t.Run("Missing Basic authentication", func(t *testing.T) {
		mockResponseWriter.EXPECT().WriteHeader(403)
		mockResponseWriter.EXPECT().Header().Return(req.Header)
		mockResponseWriter.EXPECT().Write(gomock.Any())
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Not a valid Basic authentication", func(t *testing.T) {
		req.Header.Set("Authorization", "Dont match regexp")
		mockResponseWriter.EXPECT().WriteHeader(403)
		mockResponseWriter.EXPECT().Header().Return(req.Header)
		mockResponseWriter.EXPECT().Write(gomock.Any())
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Basic authentication is not a base 64 value", func(t *testing.T) {
		var invalidBase64 = "AB"
		req.Header.Set("Authorization", "Basic "+invalidBase64)
		mockResponseWriter.EXPECT().WriteHeader(403)
		mockResponseWriter.EXPECT().Header().Return(req.Header)
		mockResponseWriter.EXPECT().Write(gomock.Any())
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Basic authentication decoded value is not like 'type:secret=qwerty,token=abcdef-789www'", func(t *testing.T) {
		var basicAuthenticationValue = base64.StdEncoding.EncodeToString([]byte("admin=password"))
		req.Header.Set("Authorization", "Basic "+basicAuthenticationValue)
		mockResponseWriter.EXPECT().WriteHeader(403)
		mockResponseWriter.EXPECT().Header().Return(req.Header)
		mockResponseWriter.EXPECT().Write(gomock.Any())
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Recaptcha bad HTTP status", func(t *testing.T) {
		var basicAuthenticationValue = base64.StdEncoding.EncodeToString([]byte("recaptcha:secret=abcdef,token=123456"))
		req.Header.Set("Authorization", "Basic "+basicAuthenticationValue)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(400)
		})
		mockResponseWriter.EXPECT().WriteHeader(403)
		mockResponseWriter.EXPECT().Header().Return(req.Header)
		mockResponseWriter.EXPECT().Write(gomock.Any())
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Invalid recaptcha code", func(t *testing.T) {
		var basicAuthenticationValue = base64.StdEncoding.EncodeToString([]byte("recaptcha:secret=abcdef,token=123456"))
		req.Header.Set("Authorization", "Basic "+basicAuthenticationValue)
		mockRecaptchaHandler.EXPECT().ServeHTTP(gomock.Any(), gomock.Any()).Do(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"success":false}`))
		})
		mockResponseWriter.EXPECT().WriteHeader(403)
		mockResponseWriter.EXPECT().Header().Return(req.Header)
		mockResponseWriter.EXPECT().Write(gomock.Any())
		authHandler.ServeHTTP(mockResponseWriter, &req)
	})

	t.Run("Recaptcha code is valid", func(t *testing.T) {
		var basicAuthenticationValue = base64.StdEncoding.EncodeToString([]byte("recaptcha:secret=abcdef,token=abcdef"))
		req.Header.Set("Authorization", "Basic "+basicAuthenticationValue)
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
	var realm = "master"
	var user = apiregister.User{}
	var expectedErr = errors.New("")

	mockComponent.EXPECT().RegisterUser(ctx, realm, user).Return("", expectedErr).Times(1)
	var _, err = component.RegisterUser(ctx, realm, user)
	assert.Equal(t, expectedErr, err)
}
