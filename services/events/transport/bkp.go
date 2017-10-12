package transport
//
//
//import (
//"testing"
//"net/http"
//"net/http/httptest"
//"github.com/stretchr/testify/assert"
//"strings"
//"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
//"github.com/google/flatbuffers/go"
//"time"
//"encoding/base64"
//"fmt"
//)
//
//var UID int64 = 1234
//var REALM string = "realm"
//
//func TestEventTransport_decodeKeycloakEventsReceiverRequest_ValidAdminEvent(t *testing.T) {
//	var req1 *http.Request
//	{
//		byteAdminEvent := createAdminEvent()
//		stringAdminEvent := base64.StdEncoding.EncodeToString(byteAdminEvent)
//		body := strings.NewReader("{\"type\": \"AdminEvent\", \"Object\": \"" + stringAdminEvent + "\"}")
//		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
//	}
//
//	var res interface{}
//	{
//		var err error
//		res, err = decodeKeycloakEventsReceiverRequest(nil, req1)
//		assert.Nil(t, err)
//		assert.IsType(t, events.AdminEvent{}, res)
//	}
//
//	var adminEvent events.AdminEvent = res.(events.AdminEvent)
//	assert.Equal(t, events.OperationTypeACTION, int(adminEvent.OperationType()))
//	assert.Equal(t, UID, adminEvent.Uid())
//}
//
//func TestEventTransport_decodeKeycloakEventsReceiverRequest_ValidEvent(t *testing.T) {
//	var req1 *http.Request
//	{
//		byteEvent := createEvent()
//		stringEvent := base64.StdEncoding.EncodeToString(byteEvent)
//		body := strings.NewReader("{\"type\": \"Event\", \"Object\": \"" + stringEvent + "\"}")
//		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
//	}
//
//	var res interface{}
//	{
//		var err error
//		res, err = decodeKeycloakEventsReceiverRequest(nil, req1)
//		assert.Nil(t, err)
//		assert.IsType(t, events.Event{}, res)
//	}
//
//	var event events.Event = res.(events.Event)
//	assert.Equal(t, REALM, string(event.RealmId()))
//	assert.Equal(t, UID, event.Uid())
//}
//
//func TestEventTransport_decodeKeycloakEventsReceiverRequest_UnknownType(t *testing.T) {
//	var req1 *http.Request
//	{
//		byteEvent := createEvent()
//		stringEvent := base64.StdEncoding.EncodeToString(byteEvent)
//		body := strings.NewReader("{\"type\": \"Unknown\", \"Object\": \"" + stringEvent + "\"}")
//		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
//	}
//
//	var res interface{}
//	{
//		var err error
//		res, err = decodeKeycloakEventsReceiverRequest(nil, req1)
//		assert.Nil(t, res)
//		assert.NotNil(t, err)
//	}
//}
//
//func TestEventTransport_decodeKeycloakEventsReceiverRequest_InvalidObject(t *testing.T) {
//	var req1 *http.Request
//	{
//		body := strings.NewReader("{\"type\": \"Event\", \"Object\": \"test\"}")
//		req1 = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
//	}
//
//	var res interface{}
//	{
//		var err error
//		res, err = decodeKeycloakEventsReceiverRequest(nil, req1)
//		assert.Nil(t, res)
//		assert.NotNil(t, err)
//		fmt.Println(err.Error())
//	}
//}
//
//
//func TestFlat_FlatAndUnflat(t *testing.T) {
//	byteAdminEvent := createAdminEvent()
//	var adminEvent *events.AdminEvent
//	adminEvent= events.GetRootAsAdminEvent(byteAdminEvent, 0)
//
//	assert.Equal(t, int8(3), (*adminEvent).OperationType())
//	assert.Equal(t, UID, (*adminEvent).Uid())
//}
//
//func createAdminEvent() ([]byte){
//	builder := flatbuffers.NewBuilder(0)
//	events.AdminEventStart(builder)
//	events.AdminEventAddTime(builder, time.Now().Unix())
//	events.AdminEventAddUid(builder, UID)
//	events.AdminEventAddOperationType(builder, events.OperationTypeACTION)
//	adminEventOffset := events.AdminEventEnd(builder)
//	builder.Finish(adminEventOffset)
//	return builder.FinishedBytes()
//}
//
//func createEvent() ([]byte){
//	builder := flatbuffers.NewBuilder(0)
//	realmStr := builder.CreateString(REALM)
//	events.EventStart(builder)
//	events.EventAddTime(builder, time.Now().Unix())
//	events.EventAddUid(builder, UID)
//	events.EventAddRealmId(builder, realmStr)
//	eventOffset := events.EventEnd(builder)
//	builder.Finish(eventOffset)
//	return builder.FinishedBytes()
//}
