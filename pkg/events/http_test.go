package events

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPManagementHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var managementHandler1 = MakeEventsHandler(keycloakb.ToGoKitEndpoint(MakeGetEventsEndpoint(mockComponent)), log.NewNopLogger())

	r := mux.NewRouter()
	r.Handle("/events", managementHandler1)

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Get - 200 with JSON body returned
	{
		var params map[string]string
		params = make(map[string]string)
		params[prmPathRealm] = "master"

		var eventsResp = api.AuditEventsRepresentation{}
		var event = api.AuditRepresentation{
			AuditID:   456,
			RealmName: params[prmPathRealm],
			Origin:    "back-office",
		}
		eventsResp.Events = append(eventsResp.Events, event)
		eventsJSON, _ := json.MarshalIndent(eventsResp, "", " ")

		mockComponent.EXPECT().GetEvents(gomock.Any(), params).Return(eventsResp, nil).Times(1)

		res, err := http.Get(ts.URL + "/events?realmTarget=master&unused=value")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		assert.Equal(t, string(eventsJSON), buf.String())
	}
}
