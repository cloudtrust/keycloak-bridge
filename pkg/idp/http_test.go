package idp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/idp/mock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestHTTPIdpHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var realm = "example"
	var apiIdp = createTestAPIIdp()
	var apiMapper = createTestAPIIdpMapper()

	var idpHandler = MakeIdpHandler(keycloakb.ToGoKitEndpoint(MakeCreateIdentityProviderEndpoint(mockComponent)), mockLogger)
	var idpHandler2 = MakeIdpHandler(keycloakb.ToGoKitEndpoint(MakeGetIdentityProviderEndpoint(mockComponent)), mockLogger)
	var idpHandler3 = MakeIdpHandler(keycloakb.ToGoKitEndpoint(MakeCreateIdentityProviderMapperEndpoint(mockComponent)), mockLogger)

	r := mux.NewRouter()
	r.Handle("/idp/realms/{realm}/identity-providers", idpHandler)
	r.Handle("/idp/realms/{realm}/identity-providers/{provider}", idpHandler2)
	r.Handle("/idp/realms/{realm}/identity-providers/{provider}/mappers", idpHandler3)

	ts := httptest.NewServer(r)
	defer ts.Close()

	t.Run("Create identity provider", func(t *testing.T) {
		mockComponent.EXPECT().CreateIdentityProvider(gomock.Any(), realm, apiIdp).Return(nil)

		idpJSON, _ := json.Marshal(apiIdp)
		body := strings.NewReader(string(idpJSON))

		res, err := http.Post(ts.URL+"/idp/realms/"+realm+"/identity-providers", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("Get identity provider", func(t *testing.T) {
		mockComponent.EXPECT().GetIdentityProvider(gomock.Any(), realm, idpAlias).Return(apiIdp, nil)

		res, err := http.Get(ts.URL + "/idp/realms/" + realm + "/identity-providers/" + idpAlias)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("Create identity provider mapper", func(t *testing.T) {
		mockComponent.EXPECT().CreateIdentityProviderMapper(gomock.Any(), realm, idpAlias, apiMapper).Return(nil)

		mapperJSON, _ := json.Marshal(apiMapper)
		body := strings.NewReader(string(mapperJSON))

		res, err := http.Post(ts.URL+"/idp/realms/"+realm+"/identity-providers/"+idpAlias+"/mappers", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
}
