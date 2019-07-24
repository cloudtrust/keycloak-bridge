package statistics

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/cloudtrust/common-service/log"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPStatisticsHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var managementHandler1 = MakeStatisticsHandler(keycloakb.ToGoKitEndpoint(MakeGetStatisticsEndpoint(mockComponent)), log.NewNopLogger())

	r := mux.NewRouter()
	r.Handle("/statistics/realm/{realm}", managementHandler1)

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Get - 200 with JSON body returned
	{
		var params map[string]string
		params = make(map[string]string)
		params["realm"] = "master"

		var stats = api.StatisticsRepresentation{}
		statsJSON, _ := json.MarshalIndent(stats, "", " ")

		mockComponent.EXPECT().GetStatistics(gomock.Any(), gomock.Any()).Return(stats, nil).Times(1)

		res, err := http.Get(ts.URL + "/statistics/realm/master")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, string(statsJSON), buf.String())
	}
}
