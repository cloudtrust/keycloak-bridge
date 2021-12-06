package export

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/export/mock"
	keycloak "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestHTTPExportHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var exportHandler = MakeHTTPExportHandler(MakeExportEndpoint(mockComponent))

	var (
		realms = []string{"master", "test", "internal"}
		reply  = map[string]interface{}{
			"master":   keycloak.RealmRepresentation{Realm: &realms[0]},
			"test":     keycloak.RealmRepresentation{Realm: &realms[1]},
			"internal": keycloak.RealmRepresentation{Realm: &realms[2]},
		}
		ctx = context.Background()
	)

	// HTTP request.
	var body = strings.NewReader("")
	var httpReq = httptest.NewRequest("GET", "http://localhost:8888/export", body)
	var w = httptest.NewRecorder()

	// Export
	{
		mockComponent.EXPECT().Export(ctx).Return(reply, nil).Times(1)
		exportHandler.ServeHTTP(w, httpReq)
		var res = w.Result()
		var body, err = ioutil.ReadAll(res.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		var dec = map[string]keycloak.RealmRepresentation{}
		err = json.Unmarshal(body, &dec)
		assert.Nil(t, err)

		assert.Equal(t, "master", *dec["master"].Realm)
		assert.Equal(t, "test", *dec["test"].Realm)
		assert.Equal(t, "internal", *dec["internal"].Realm)
	}
}
