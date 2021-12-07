package validation

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation/mock"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPValidationHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	r := mux.NewRouter()
	r.Handle("/validation/users/{userID}", MakeValidationHandler(keycloakb.ToGoKitEndpoint(MakeGetUserEndpoint(mockComponent)), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	{
		mockComponent.EXPECT().GetUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(api.UserRepresentation{}, nil).Times(1)

		res, err := http.Post(ts.URL+"/validation/users/12345678-5824-5555-5656-123456789654", "", nil)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, "{}", buf.String())
	}
}
