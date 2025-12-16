package management

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc_client "github.com/cloudtrust/keycloak-client/v2"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func responseToString(input io.ReadCloser) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(input)
	return buf.String()
}

func responseToMap(input io.ReadCloser) map[string]string {
	var bytes = []byte(responseToString(input))
	var res map[string]string
	_ = json.Unmarshal(bytes, &res)
	return res
}

func TestHTTPManagementHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		url      = "http://api.domain.ch/users/123456-7890-abcd-efghijkl"
		endpoint = func(ctx context.Context, req interface{}) (interface{}, error) {
			var m = req.(map[string]string)
			if realm, ok := m["realm"]; ok {
				switch realm {
				case "notfound":
					return nil, errorhandler.CreateNotFoundError("realm")
				case "kcclienterror":
					return nil, kc_client.HTTPError{
						HTTPStatus: http.StatusBadGateway,
						Message:    "kc_client error",
					}
				case "create":
					return LocationHeader{
						URL: url,
					}, nil
				}
			}
			return req, nil
		}
		managementHandler = MakeManagementHandler(keycloakb.ToGoKitEndpoint(endpoint), log.NewNopLogger())
	)

	r := mux.NewRouter()
	r.Path("/realms/{realm}").Methods("GET").Handler(managementHandler)
	r.Path("/realms/{realm}").Methods("POST").Handler(managementHandler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	t.Run("Not found", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/realms/notfound")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, res.StatusCode)
	})
	t.Run("Success with JSON response", func(t *testing.T) {
		var email = "toto@toto.com"
		res, err := http.Get(ts.URL + "/realms/master?email=" + email)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		var resp = responseToMap(res.Body)
		assert.Equal(t, email, resp["email"])
	})
	t.Run("Invalid input parameter", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/realms/master?email=" + strings.Repeat("A", 129))
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
	t.Run("kc_client test case", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/realms/kcclienterror")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadGateway, res.StatusCode)

		var resp = responseToString(res.Body)
		assert.Equal(t, "keycloak-bridge.unknowError", resp)
	})
	t.Run("location test case", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/realms/create")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusCreated, res.StatusCode)
		assert.Equal(t, url, res.Header.Get("Location"))
	})
	t.Run("Invalid context-key param", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/realms/master?context-key=invalid-uuid")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
	t.Run("Valid context-key param", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/realms/master?context-key=122b6480-9dc2-4a03-91de-e63b2f129518")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
}
