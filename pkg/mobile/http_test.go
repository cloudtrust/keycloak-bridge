package mobilepkg

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/mobile"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/mobile/mock"
	"go.uber.org/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPMobileHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMobileComponent = mock.NewComponent(mockCtrl)

	r := mux.NewRouter()
	r.Handle("/path/to/account", MakeMobileHandler(keycloakb.ToGoKitEndpoint(MakeGetUserInformationEndpoint(mockMobileComponent)), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	{
		mockMobileComponent.EXPECT().GetUserInformation(gomock.Any()).Return(api.UserInformationRepresentation{}, nil).Times(1)

		var input []byte
		res, err := http.Post(ts.URL+"/path/to/account", "application/json", ioutil.NopCloser(bytes.NewBuffer(input)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, "{}", buf.String())
	}
}
