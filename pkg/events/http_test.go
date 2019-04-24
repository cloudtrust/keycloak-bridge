package events

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=EventsComponent=EventsComponent github.com/cloudtrust/keycloak-bridge/pkg/events EventsComponent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPManagementHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewEventsComponent(mockCtrl)

	var managementHandler1 = MakeEventsHandler(MakeGetEventsEndpoint(mockComponent))

	r := mux.NewRouter()
	r.Handle("/events", managementHandler1)

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Get - 200 with JSON body returned
	{
		var params map[string]string
		params = make(map[string]string)
		params["realmTarget"] = "master"

		var eventsResp = api.AuditEventsRepresentation{}
		var event = api.AuditRepresentation{
			AuditID:   456,
			RealmName: params["realm"],
			Origin:    "back-office",
		}
		eventsResp.Events = append(eventsResp.Events, event)
		eventsJSON, _ := json.MarshalIndent(eventsResp, "", " ")

		mockComponent.EXPECT().GetEvents(gomock.Any(), params).Return(eventsResp, nil).Times(1)

		res, err := http.Get(ts.URL + "/events?realmTarget=master&unused=value")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, string(eventsJSON), buf.String())
	}
}
