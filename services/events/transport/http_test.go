package transport


import (
	"testing"
	"net/http"
	"net/http/httptest"
	"github.com/stretchr/testify/assert"
	"strings"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
	"github.com/google/flatbuffers/go"
	"time"
	"encoding/base64"
)

var UID int64 = 1234
var REALM string = "realm"

func TestEventTransport_decodeKeycloakEventsReceiverRequest_ValidAdminEvent(t *testing.T) {
	var req1 *http.Request
	var byteAdminEvent []byte = createAdminEvent()
	{
		stringAdminEvent := base64.StdEncoding.EncodeToString(byteAdminEvent)
		body := strings.NewReader("{\"type\": \"AdminEvent\", \"Object\": \"" + stringAdminEvent + "\"}")
		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
	}

	var res interface{}
	{
		var err error
		res, err = decodeKeycloakEventsReceiverRequest(nil, req1)
		assert.Nil(t, err)
		assert.IsType(t, EventRequest{}, res)
	}

	var eventMuxReq EventRequest = res.(EventRequest)
	assert.Equal(t, "AdminEvent", eventMuxReq.Type)
	assert.Equal(t, byteAdminEvent, eventMuxReq.Object)
}


func TestEventTransport_decodeKeycloakEventsReceiverRequest_ValidEvent(t *testing.T) {
	var req1 *http.Request
	var byteEvent []byte = createEvent()
	{
		stringEvent := base64.StdEncoding.EncodeToString(byteEvent)
		body := strings.NewReader("{\"type\": \"Event\", \"Object\": \"" + stringEvent + "\"}")
		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
	}

	var res interface{}
	{
		var err error
		res, err = decodeKeycloakEventsReceiverRequest(nil, req1)
		assert.Nil(t, err)
		assert.IsType(t, EventRequest{}, res)
	}

	var eventMuxReq EventRequest = res.(EventRequest)
	assert.Equal(t, "Event", eventMuxReq.Type)
	assert.Equal(t, byteEvent, eventMuxReq.Object)
}

func TestEventTransport_decodeKeycloakEventsReceiverRequest_UnknownType(t *testing.T) {
	var req1 *http.Request
	{
		byteEvent := createEvent()
		stringEvent := base64.StdEncoding.EncodeToString(byteEvent)
		body := strings.NewReader("{\"type\": \"Unknown\", \"Object\": \"" + stringEvent + "\"}")
		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
	}

	var err error
	_, err = decodeKeycloakEventsReceiverRequest(nil, req1)
	assert.NotNil(t, err)
	assert.IsType(t, ErrInvalidArgument{}, err)
}

func TestEventTransport_decodeKeycloakEventsReceiverRequest_InvalidObject(t *testing.T) {
	var req1 *http.Request
	{
		body := strings.NewReader("{\"type\": \"Event\", \"Object\": \"test\"}")
		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
	}

	var err error
	_, err = decodeKeycloakEventsReceiverRequest(nil, req1)
	assert.NotNil(t, err)
	assert.IsType(t, ErrInvalidArgument{}, err)
}


func createAdminEvent() ([]byte){
	builder := flatbuffers.NewBuilder(0)
	events.AdminEventStart(builder)
	events.AdminEventAddTime(builder, time.Now().Unix())
	events.AdminEventAddUid(builder, UID)
	events.AdminEventAddOperationType(builder, events.OperationTypeACTION)
	adminEventOffset := events.AdminEventEnd(builder)
	builder.Finish(adminEventOffset)
	return builder.FinishedBytes()
}

func createEvent() ([]byte){
	builder := flatbuffers.NewBuilder(0)
	realmStr := builder.CreateString(REALM)
	events.EventStart(builder)
	events.EventAddTime(builder, time.Now().Unix())
	events.EventAddUid(builder, UID)
	events.EventAddRealmId(builder, realmStr)
	eventOffset := events.EventEnd(builder)
	builder.Finish(eventOffset)
	return builder.FinishedBytes()
}