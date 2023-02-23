package account

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	account_api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPAccountHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockAccountComponent = mock.NewComponent(mockCtrl)

	r := mux.NewRouter()
	r.Handle("/path/to/{realm}/password", MakeAccountHandler(keycloakb.ToGoKitEndpoint(MakeUpdatePasswordEndpoint(mockAccountComponent)), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	{
		body := account_api.UpdatePasswordBody{
			CurrentPassword: "current",
			NewPassword:     "new",
			ConfirmPassword: "confirm",
		}
		json, _ := json.MarshalIndent(body, "", " ")

		mockAccountComponent.EXPECT().UpdatePassword(gomock.Any(), body.CurrentPassword, body.NewPassword, body.ConfirmPassword).Return(nil).Times(1)

		res, err := http.Post(ts.URL+"/path/to/master/password", "application/json", ioutil.NopCloser(bytes.NewBuffer(json)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, "", buf.String())
	}
}
