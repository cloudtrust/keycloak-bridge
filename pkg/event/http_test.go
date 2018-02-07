package event

import (
	"context"
	"encoding/base64"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"

	"github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
)

func TestEventTransport_decodeKeycloakEventsReceiverRequest_ValidAdminEvent(t *testing.T) {
	var byteAdminEvent = createhttpAdminEvent(1234)
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

	var byteEvent = createhttpEvent(1234, "realm")
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
	var byteEvent = createhttpEvent(1234, "realm")
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

func createhttpAdminEvent(uid int64) []byte {
	var builder = flatbuffers.NewBuilder(0)
	fb.AdminEventStart(builder)
	fb.AdminEventAddTime(builder, time.Now().Unix())
	fb.AdminEventAddUid(builder, uid)
	fb.AdminEventAddOperationType(builder, fb.OperationTypeACTION)
	var adminEventOffset = fb.AdminEventEnd(builder)
	builder.Finish(adminEventOffset)
	return builder.FinishedBytes()
}

func createhttpEvent(uid int64, realm string) []byte {
	var builder = flatbuffers.NewBuilder(0)
	var realmStr = builder.CreateString(realm)
	fb.EventStart(builder)
	fb.EventAddTime(builder, time.Now().Unix())
	fb.EventAddUid(builder, uid)
	fb.EventAddRealmId(builder, realmStr)
	var eventOffset = fb.EventEnd(builder)
	builder.Finish(eventOffset)
	return builder.FinishedBytes()
}
