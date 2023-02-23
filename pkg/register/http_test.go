package register

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPRegisterHandler(t *testing.T) {
	var URL = "/register"
	var errorMessage = "error-message"

	r := mux.NewRouter()
	r.Handle(URL, MakeRegisterHandler(func(ctx context.Context, request interface{}) (response interface{}, err error) {
		var m = request.(map[string]string)
		if m[prmRealm] != "fail" {
			return m[prmRealm], nil
		}
		return m[prmRealm], errorhandler.CreateBadRequestError(errorMessage)
	}, log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	var first = "John"
	var last = "Doe"
	var body = api.UserRepresentation{
		FirstName: &first,
		LastName:  &last,
	}
	var json, _ = json.Marshal(body)

	t.Run("HTTP 200", func(t *testing.T) {
		res, err := http.Post(ts.URL+URL+"?realm=my-realm", "application/json", ioutil.NopCloser(bytes.NewBuffer(json)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, `"my-realm"`, buf.String())
	})

	t.Run("HTTP 400", func(t *testing.T) {
		res, err := http.Post(ts.URL+URL+"?realm=fail", "application/json", ioutil.NopCloser(bytes.NewBuffer(json)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.True(t, strings.Contains(buf.String(), errorMessage))
	})
}
