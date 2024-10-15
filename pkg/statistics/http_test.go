package statistics

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestHTTPStatisticsHandler(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockComponent := mock.NewComponent(mockCtrl)

	managementHandler1 := MakeStatisticsHandler(keycloakb.ToGoKitEndpoint(MakeGetStatisticsIdentificationsEndpoint(mockComponent)), log.NewNopLogger())

	r := mux.NewRouter()
	r.Handle("/statistics/realm/{realm}", managementHandler1)

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Get - 200 with JSON body returned
	{
		params := make(map[string]string)
		params[prmRealm] = "master"

		stats := api.IdentificationStatisticsRepresentation{}
		statsJSON, _ := json.MarshalIndent(stats, "", " ")

		mockComponent.EXPECT().GetStatisticsIdentifications(gomock.Any(), gomock.Any()).Return(stats, nil).Times(1)

		res, err := http.Get(ts.URL + "/statistics/realm/master")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, string(statsJSON), buf.String())
	}
}
