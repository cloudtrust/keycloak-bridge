package events

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=EventsComponent=EventsComponent github.com/cloudtrust/keycloak-bridge/pkg/events EventsComponent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/security"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/go-kit/kit/ratelimit"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPManagementHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewEventsComponent(mockCtrl)

	var managementHandler1 = MakeEventsHandler(MakeGetEventsEndpoint(mockComponent))
	var managementHandler2 = MakeEventsHandler(MakeGetEventsSummaryEndpoint(mockComponent))
	var managementHandler3 = MakeEventsHandler(MakeGetUserEventsEndpoint(mockComponent))
	var managementHandler4 = MakeEventsHandler(func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	})

	r := mux.NewRouter()
	r.Handle("/events", managementHandler1)
	r.Handle("/events/summary", managementHandler2)
	r.Handle("/events/realms/{realm}/users/{userID}/events", managementHandler3)
	r.Handle("/nil", managementHandler4)

	ts := httptest.NewServer(r)
	defer ts.Close()
	// Get - Bad request: duplicated parameter realm
	{
		res, err := http.Get(ts.URL + "/events/realms/master/users/123-456/events?first=1&realm=master")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	}

	// Get - 200 with JSON body returned
	{
		var params map[string]string
		params = make(map[string]string)
		params["realm"] = "master"

		var eventsResp = []api.AuditRepresentation{}
		var event = api.AuditRepresentation{
			AuditID:   456,
			RealmName: params["realm"],
			Origin:    "back-office",
		}
		eventsResp = append(eventsResp, event)
		eventsJSON, _ := json.MarshalIndent(eventsResp, "", " ")

		mockComponent.EXPECT().GetEvents(gomock.Any(), params).Return(eventsResp, nil).Times(1)

		res, err := http.Get(ts.URL + "/events?realm=master&unused=value")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, string(eventsJSON), buf.String())
	}

	// Get - 200 with JSON body returned
	{
		var summary api.EventSummaryRepresentation
		summary.Origins = append(summary.Origins, "origin-1", "origin-2", "origin-3")
		summary.Realms = append(summary.Realms, "realm-1")
		summary.CtEventTypes = append(summary.CtEventTypes, "ct-event-1", "ct-event2")
		eventsJSON, _ := json.MarshalIndent(summary, "", " ")

		mockComponent.EXPECT().GetEventsSummary(gomock.Any()).Return(summary, nil).Times(1)

		res, err := http.Get(ts.URL + "/events/summary")

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, string(eventsJSON), buf.String())
	}

	// Rate limit error
	{
		var summary api.EventSummaryRepresentation
		mockComponent.EXPECT().GetEventsSummary(gomock.Any()).Return(summary, ratelimit.ErrLimited).Times(1)
		res, err := http.Get(ts.URL + "/events/summary")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, "", buf.String())
	}

	// Internal error
	{
		var summary api.EventSummaryRepresentation
		mockComponent.EXPECT().GetEventsSummary(gomock.Any()).Return(summary, errors.New("error message")).Times(1)
		res, err := http.Get(ts.URL + "/events/summary")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, "", buf.String())
	}

	// Not allowed: security forbidden
	{
		var summary api.EventSummaryRepresentation
		mockComponent.EXPECT().GetEventsSummary(gomock.Any()).Return(summary, security.ForbiddenError{}).Times(1)
		res, err := http.Get(ts.URL + "/events/summary")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, "", buf.String())
	}

	// Nil response
	{
		client := &http.Client{}
		req, _ := http.NewRequest("GET", ts.URL+"/nil", nil)
		req.Header.Set("X-Forwarded-Proto", "tcp")
		res, err := client.Do(req)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		buf := new(bytes.Buffer)
		buf.ReadFrom(res.Body)
		assert.Equal(t, "", buf.String())
	}
}
