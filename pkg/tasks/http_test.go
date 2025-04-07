package tasks

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestHTTPMobileHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var endpoint = func(ctx context.Context, _ interface{}) (interface{}, error) {
		return []string{}, nil
	}

	r := mux.NewRouter()
	r.Handle("/path/to/account", MakeTasksHandler(keycloakb.ToGoKitEndpoint(endpoint), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	{
		var input []byte
		res, err := http.Post(ts.URL+"/path/to/account", "application/json", io.NopCloser(bytes.NewBuffer(input)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, "[]", buf.String())
	}
}
