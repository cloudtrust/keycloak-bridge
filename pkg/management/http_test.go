package management

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPResponse(t *testing.T) {
	// Coverage
	var kcError = CreateMissingParameterError("parameter")
	assert.Contains(t, kcError.Error(), kcError.Message)
}

func TestHTTPManagementHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var managementHandler = MakeManagementHandler(MakeGetRealmEndpoint(mockComponent))
	var managementHandler2 = MakeManagementHandler(MakeCreateUserEndpoint(mockComponent))
	var managementHandler3 = MakeManagementHandler(MakeResetPasswordEndpoint(mockComponent))

	r := mux.NewRouter()
	r.Handle("/realms/{realm}", managementHandler)
	r.Handle("/realms/{realm}/users", managementHandler2)
	r.Handle("/realms/{realm}/users/{userID}/reset-password", managementHandler3)

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Get - 200 with JSON body returned
	{
		var id = "1234-456"
		var realm = "master"

		var realmRep = api.RealmRepresentation{
			Id:    &id,
			Realm: &realm,
		}
		realmJSON, _ := json.MarshalIndent(realmRep, "", " ")

		mockComponent.EXPECT().GetRealm(gomock.Any(), "master").Return(realmRep, nil).Times(1)

		res, err := http.Get(ts.URL + "/realms/master")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, string(realmJSON), buf.String())
	}

	// Post - 201 with Location header
	{
		var username = "toto"
		var email = "toto@elca.ch"

		var user = api.UserRepresentation{
			Username: &username,
			Email:    &email,
		}
		userJSON, _ := json.Marshal(user)

		mockComponent.EXPECT().CreateUser(gomock.Any(), "master", user).Return("https://elca.com/auth/admin/realms/master/users/12456", nil).Times(1)

		var body = strings.NewReader(string(userJSON))
		res, err := http.Post(ts.URL+"/realms/master/users", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusCreated, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
		valid, _ := regexp.MatchString("http://127.0.0.1:[0-9]{0,5}/management/realms/master/users/12456", res.Header.Get("Location"))
		assert.True(t, valid)
	}

	// Get - 200 without body content
	{
		var password = "P@ssw0rd"

		var passwordRep = api.PasswordRepresentation{
			Value: &password,
		}
		passwordJSON, _ := json.Marshal(passwordRep)

		mockComponent.EXPECT().ResetPassword(gomock.Any(), "master", "123456", gomock.Any()).Return(nil).Times(1)

		var body = strings.NewReader(string(passwordJSON))
		res, err := http.Post(ts.URL+"/realms/master/users/123456/reset-password", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
	}

}

func TestHTTPErrorHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var managementHandler = MakeManagementHandler(MakeCreateUserEndpoint(mockComponent))

	r := mux.NewRouter()
	r.Handle("/realms/{realm}/users", managementHandler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var username = "toto"
	var email = "toto@elca.ch"

	var user = api.UserRepresentation{
		Username: &username,
		Email:    &email,
	}
	userJSON, _ := json.Marshal(user)

	// Internal server error.
	{
		mockComponent.EXPECT().CreateUser(gomock.Any(), "master", user).Return("", fmt.Errorf("Unexpected Error")).Times(1)

		var body = strings.NewReader(string(userJSON))
		res, err := http.Post(ts.URL+"/realms/master/users", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
	}

	// Forbidden error.
	{
		mockComponent.EXPECT().CreateUser(gomock.Any(), "master", user).Return("", ForbiddenError{}).Times(1)

		var body = strings.NewReader(string(userJSON))
		res, err := http.Post(ts.URL+"/realms/master/users", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
	}

	// Bad request.
	{
		var body = strings.NewReader("?/%&asd==")
		res, err := http.Post(ts.URL+"/realms/master/users", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
	}

	// Keycloak Error
	{
		var kcError = kc_client.HTTPError{
			HTTPStatus: 404,
			Message:    "Not found",
		}
		mockComponent.EXPECT().CreateUser(gomock.Any(), "master", user).Return("", kcError).Times(1)

		var body = strings.NewReader(string(userJSON))
		res, err := http.Post(ts.URL+"/realms/master/users", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
	}

	// HTTPResponse Error
	{
		var kcError = HTTPError{
			Status:  401,
			Message: "Unauthorized",
		}
		mockComponent.EXPECT().CreateUser(gomock.Any(), "master", user).Return("", kcError).Times(1)

		var body = strings.NewReader(string(userJSON))
		res, err := http.Post(ts.URL+"/realms/master/users", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
	}
}

func TestHTTPXForwardHeaderHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var managementHandler = MakeManagementHandler(MakeCreateUserEndpoint(mockComponent))

	r := mux.NewRouter()
	r.Handle("/realms/{realm}/users", managementHandler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	client := &http.Client{}

	// Check Host and X-Forward-Proto have impact on location returned
	{
		var username = "toto"
		var email = "toto@elca.ch"

		var user = api.UserRepresentation{
			Username: &username,
			Email:    &email,
		}
		userJSON, _ := json.Marshal(user)

		mockComponent.EXPECT().CreateUser(gomock.Any(), "master", user).Return("https://elca.com/auth/admin/realms/master/users/12456", nil).Times(1)

		var body = strings.NewReader(string(userJSON))

		req, err := http.NewRequest("POST", ts.URL+"/realms/master/users", body)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Host = "toto.com"
		res, err := client.Do(req)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusCreated, res.StatusCode)
		assert.Equal(t, http.NoBody, res.Body)
		valid, _ := regexp.MatchString("https://toto.com/management/realms/master/users/12456", res.Header.Get("Location"))
		assert.True(t, valid)
	}
}
