package kyc

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestKYCRegisterHandler(t *testing.T) {
	var URL = "/kyc/user"

	r := mux.NewRouter()
	r.Handle(URL+"/{userId}", MakeKYCHandler(func(ctx context.Context, request interface{}) (response interface{}, err error) {
		var m = request.(map[string]string)
		return m[PrmUserID] + ":" + m[PrmQryUserName], nil
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
		res, err := http.Post(ts.URL+URL+"/abcd0123-abcd-0123-xxxx-123456789012?username=my-username", "application/json", ioutil.NopCloser(bytes.NewBuffer(json)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, `"abcd0123-abcd-0123-xxxx-123456789012:my-username"`, buf.String())
	})

	t.Run("HTTP 400", func(t *testing.T) {
		res, err := http.Post(ts.URL+URL+"/abcd0123", "application/json", ioutil.NopCloser(bytes.NewBuffer(json)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}
