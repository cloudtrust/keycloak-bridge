package configuration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	realm      = "trustid"
	contextKey = "19251660-f869-11ec-b939-0242ac120002"
)

func TestHTTPConfigurationHandler(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	r := mux.NewRouter()
	r.Handle("/configuration/realms/{realm}/identification", MakeConfigurationHandler(
		func(ctx context.Context, request interface{}) (response interface{}, err error) {
			var m = request.(map[string]string)
			return m[prmRealmName] + ":" + m[prmContextKey], nil
		}, log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	t.Run("Success", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/configuration/realms/" + realm + "/identification?context-key=" + contextKey)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, `"trustid:19251660-f869-11ec-b939-0242ac120002"`, buf.String())
	})

	t.Run("Invalid context-key", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/configuration/realms/" + realm + "/identification?context-key=a")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("Invalid realm name", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/configuration/realms/realm!/identification?context-key=" + contextKey)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}
