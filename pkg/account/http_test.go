package account

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	"github.com/go-kit/kit/log"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPAccountHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	r := mux.NewRouter()
	r.Handle("/path/to/{realm}/password", MakeAccountHandler(keycloakb.ToGoKitEndpoint(MakeUpdatePasswordEndpoint(mockComponent)), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	{
		body := UpdatePasswordBody{
			CurrentPassword: "current",
			NewPassword:     "new",
			ConfirmPassword: "confirm",
		}
		json, _ := json.MarshalIndent(body, "", " ")

		mockComponent.EXPECT().UpdatePassword(gomock.Any(), body.CurrentPassword, body.NewPassword, body.ConfirmPassword).Return(nil).Times(1)

		res, err := http.Post(ts.URL+"/path/to/master/password", "application/json", ioutil.NopCloser(bytes.NewBuffer(json)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, "", buf.String())
	}
}
