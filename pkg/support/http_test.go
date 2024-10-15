package support

import (
	"bytes"
	"context"
	"fmt"
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	endpoint := func(ctx context.Context, req interface{}) (interface{}, error) {
		m := req.(map[string]string)
		return m[prmQryEmail], nil
	}

	r := mux.NewRouter()
	r.Handle("/path/to/account", MakeSupportHandler(keycloakb.ToGoKitEndpoint(endpoint), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	{
		sampleEmail := "me@domain.net"
		doublequote := '"'
		res, err := http.Get(ts.URL + "/path/to/account?email=" + sampleEmail)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, fmt.Sprintf("%c%s%c", doublequote, sampleEmail, doublequote), buf.String())
	}
}
