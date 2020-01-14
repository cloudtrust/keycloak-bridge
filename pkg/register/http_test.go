package register

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPRegisterHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockRegisterComponent = mock.NewComponent(mockCtrl)

	r := mux.NewRouter()
	r.Handle("/register/realm/{realm}/user", MakeRegisterHandler(keycloakb.ToGoKitEndpoint(MakeRegisterUserEndpoint(mockRegisterComponent)), log.NewNopLogger()))

	ts := httptest.NewServer(r)
	defer ts.Close()

	var first = "John"
	var last = "Doe"

	{
		body := api.User{
			FirstName: &first,
			LastName:  &last,
		}
		json, _ := json.Marshal(body)

		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), "master", gomock.Any()).Return("abc", nil).Times(1)

		res, err := http.Post(ts.URL+"/register/realm/master/user", "application/json", ioutil.NopCloser(bytes.NewBuffer(json)))

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, `"abc"`, buf.String())
	}
}
