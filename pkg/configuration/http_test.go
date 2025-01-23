package configuration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/configuration/mock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestHTTPConfigurationHandler(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockConfigurationComponent := mock.NewComponent(mockCtrl)

	const (
		realm             = "trustid"
		contextKey        = "19251660-f869-11ec-b939-0242ac120002"
		identificationURI = "http://identification-uri"
	)

	r := mux.NewRouter()
	r.Handle("/configuration/realms/{realm}/identification", MakeConfigurationHandler(keycloakb.ToGoKitEndpoint(MakeGetIdentificationURIEndpoint(mockConfigurationComponent)), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	{
		mockConfigurationComponent.EXPECT().GetIdentificationURI(gomock.Any(), realm, contextKey).Return(identificationURI, nil)

		res, err := http.Get(ts.URL + "/configuration/realms/" + realm + "/identification?context-key=" + contextKey)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		assert.Nil(t, err)

		// Remove quotes from the server response
		result := strings.Trim(string(body), "\"")
		assert.Equal(t, identificationURI, result)
	}
}
