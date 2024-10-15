package register

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	logger "github.com/cloudtrust/common-service/v2/log"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func configureMock(mockResponse *mock.ResponseWriter, statusCode int, header http.Header) {
	mockResponse.EXPECT().WriteHeader(statusCode)
	mockResponse.EXPECT().Header().Return(header)
	mockResponse.EXPECT().Write(gomock.Any())
}

func TestMakeHTTPRecaptchaValidationMW(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPHandler := mock.NewHandler(mockCtrl)
	mockRecaptchaHandler := mock.NewHandler(mockCtrl)
	mockResponseWriter := mock.NewResponseWriter(mockCtrl)

	recaptchaPath := "/recaptcha"
	recaptchaSecret := "thesecretfortherecaptchaverifyprocess"
	r := mux.NewRouter()
	r.Handle(recaptchaPath, mockRecaptchaHandler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	authHandler := MakeHTTPRecaptchaValidationMW(ts.URL+recaptchaPath, recaptchaSecret, logger.NewNopLogger())(mockHTTPHandler)

	req := http.Request{
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockComponent := mock.NewComponent(mockCtrl)
	component := MakeAuthorizationRegisterComponentMW(logger.NewNopLogger())(mockComponent)

	ctx := context.TODO()
	socialRealm := "social"
	realm := "my-realm"
	user := apiregister.UserRepresentation{}
	expectedErr := errors.New("")

	t.Run("RegisterUser", func(t *testing.T) {
		mockComponent.EXPECT().RegisterUser(ctx, socialRealm, realm, user, nil).Return("", expectedErr)
		_, err := component.RegisterUser(ctx, socialRealm, realm, user, nil)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("GetConfiguration", func(t *testing.T) {
		mockComponent.EXPECT().GetConfiguration(ctx, realm).Return(apiregister.ConfigurationRepresentation{}, expectedErr)
		_, err := component.GetConfiguration(ctx, realm)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("GetUserProfile", func(t *testing.T) {
		mockComponent.EXPECT().GetUserProfile(ctx, realm).Return(apicommon.ProfileRepresentation{}, expectedErr)
		_, err := component.GetUserProfile(ctx, realm)
		assert.Equal(t, expectedErr, err)
	})
}
