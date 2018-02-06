package event

import (
	"context"
	"encoding/base64"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	events "github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/fb"
	"github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
)

var UID int64 = 1234
var REALM = "realm"

func TestEventTransport_decodeKeycloakEventsReceiverRequest_ValidAdminEvent(t *testing.T) {
	var byteAdminEvent = createAdminEvent()
	var stringAdminEvent = base64.StdEncoding.EncodeToString(byteAdminEvent)
	var body = strings.NewReader("{\"type\": \"AdminEvent\", \"Obj\": \"" + stringAdminEvent + "\"}")
	var req = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)

	var res interface{}
	var err error
	res, err = decodeKeycloakEventsReceiverRequest(context.Background(), req)
	assert.Nil(t, err)
	assert.IsType(t, EventRequest{}, res)

	var eventMuxReq = res.(EventRequest)
	assert.Equal(t, "AdminEvent", eventMuxReq.Type)
	assert.Equal(t, byteAdminEvent, eventMuxReq.Object)
}

func TestEventTransport_decodeKeycloakEventsReceiverRequest_ValidEvent(t *testing.T) {

	var byteEvent = createEvent()
	var stringEvent = base64.StdEncoding.EncodeToString(byteEvent)
	var body io.Reader = strings.NewReader("{\"type\": \"Event\", \"Obj\": \"" + stringEvent + "\"}")
	var req = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)

	var res interface{}
	var err error
	res, err = decodeKeycloakEventsReceiverRequest(context.Background(), req)
	assert.Nil(t, err)
	assert.IsType(t, EventRequest{}, res)

	var eventMuxReq = res.(EventRequest)
	assert.Equal(t, "Event", eventMuxReq.Type)
	assert.Equal(t, byteEvent, eventMuxReq.Object)
}

func TestEventTransport_decodeKeycloakEventsReceiverRequest_UnknownType(t *testing.T) {
	var byteEvent = createEvent()
	var stringEvent = base64.StdEncoding.EncodeToString(byteEvent)
	var body io.Reader = strings.NewReader("{\"type\": \"Unknown\", \"Obj\": \"" + stringEvent + "\"}")
	var req = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)

	var err error
	_, err = decodeKeycloakEventsReceiverRequest(context.Background(), req)
	assert.NotNil(t, err)
	assert.IsType(t, ErrInvalidArgument{}, err)
}

func TestEventTransport_decodeKeycloakEventsReceiverRequest_InvalidObject(t *testing.T) {
	var body = strings.NewReader("{\"type\": \"Event\", \"Obj\": \"test\"}")
	var req = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)

	var err error
	_, err = decodeKeycloakEventsReceiverRequest(context.Background(), req)
	assert.NotNil(t, err)
	assert.IsType(t, ErrInvalidArgument{}, err)
}

func createAdminEvent() []byte {
	var builder = flatbuffers.NewBuilder(0)
	events.AdminEventStart(builder)
	events.AdminEventAddTime(builder, time.Now().Unix())
	events.AdminEventAddUid(builder, UID)
	events.AdminEventAddOperationType(builder, events.OperationTypeACTION)
	var adminEventOffset = events.AdminEventEnd(builder)
	builder.Finish(adminEventOffset)
	return builder.FinishedBytes()
}

func createEvent() []byte {
	var builder = flatbuffers.NewBuilder(0)
	var realmStr = builder.CreateString(REALM)
	events.EventStart(builder)
	events.EventAddTime(builder, time.Now().Unix())
	events.EventAddUid(builder, UID)
	events.EventAddRealmId(builder, realmStr)
	var eventOffset = events.EventEnd(builder)
	builder.Finish(eventOffset)
	return builder.FinishedBytes()
}
