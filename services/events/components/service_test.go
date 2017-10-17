package components

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
	"github.com/google/flatbuffers/go"
	"time"
	"errors"
	"fmt"
)

var UID int64 = 1234
var REALM string = "realm"

func TestEventComponents_NewEventService(t *testing.T) {
	var eventService EventService
	{
		fnStd := func(eventMap map[string]string) error{
			return nil
		}

		fnErr := func(eventMap map[string]string) error{
			return errors.New("Failed")
		}

		var tStd = [](func(map[string]string) error) {fnStd}
		var tErr = [](func(map[string]string) error) {fnErr}
		eventService = NewEventService(tStd, tErr)
	}

	{
		var eventStd *events.Event = createEvent(events.EventTypeCLIENT_DELETE)
		res, err := eventService.Event(nil, eventStd)
		assert.Equal(t, "ok", res)
		assert.Nil(t, err)
	}

	{
		var eventErr *events.Event = createEvent(events.EventTypeCLIENT_DELETE_ERROR)
		res, err := eventService.Event(nil, eventErr)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}


func TestEventComponents_NewAdminEventService(t *testing.T) {
	var adminEventService AdminEventService
	var ch = make(chan string, 1)
	{
		fnCreate := func(eventMap map[string]string) (error){
			ch <-  "CREATE"
			return nil
		}

		fnUpdate := func(eventMap map[string]string) (error){
			ch <-  "UPDATE"
			return nil
		}

		fnDelete := func(eventMap map[string]string) (error){
			ch <-  "DELETE"
			return nil
		}

		fnAction := func(eventMap map[string]string) (error){
			ch <-  "ACTION"
			return nil
		}

		var tCreate = [](func(map[string]string) (error)) {fnCreate}
		var tUpdate = [](func(map[string]string) (error)) {fnUpdate}
		var tDelete = [](func(map[string]string) (error)) {fnDelete}
		var tAction = [](func(map[string]string) (error)) {fnAction}
		adminEventService = NewAdminEventService(tCreate, tUpdate, tDelete, tAction)
	}

	fn := func (operationType int8){
		var adminEvt *events.AdminEvent = createAdminEvent(events.OperationTypeCREATE)
		_, err := adminEventService.AdminEvent(nil, adminEvt)

		assert.Equal(t, getOperationTypeName(events.OperationTypeCREATE), <- ch)
		assert.Nil(t, err)
	}

	operationTypes := [4]int8 {events.OperationTypeCREATE,
							  events.OperationTypeUPDATE,
							  events.OperationTypeDELETE,
							  events.OperationTypeACTION}

	for _, element := range operationTypes{
		fn(element)
	}

}


func TestEventComponents_NewMuxService(t *testing.T) {

	var muxService MuxService
	var ch = make(chan string,1)
	{
		fnEvent := func(eventMap map[string]string) (error){
			ch <-  "Event"
			return nil
		}

		fnAdminEvent := func(eventMap map[string]string) (error){
			ch <-  "AdminEvent"
			return nil
		}

		var tEvent = [](func(map[string]string) (error)) {fnEvent}
		var tAdminEvent = [](func(map[string]string) (error)) {fnAdminEvent}

		eventService := NewEventService(tEvent, tEvent)
		adminEventService := NewAdminEventService(tAdminEvent, tAdminEvent, tAdminEvent, tAdminEvent)

		muxService = NewMuxService(eventService, adminEventService)
	}

	{
		var event []byte = createEventBytes(events.EventTypeCLIENT_DELETE)
		_, err := muxService.Event(nil, "Event", event)
		assert.Equal(t, "Event", <-ch)
		assert.Nil(t, err)
	}

	{
		var adminEvent []byte = createEventBytes(events.EventTypeCLIENT_DELETE)
		_, err := muxService.Event(nil, "AdminEvent", adminEvent)
		assert.Equal(t, "AdminEvent", <-ch)
		assert.Nil(t, err)
	}

}


func TestEventComponents_eventToMap(t *testing.T) {

	builder := flatbuffers.NewBuilder(0)

	realmStr := builder.CreateString(REALM)
	clientIdStr := builder.CreateString("clientId")
	userIdStr := builder.CreateString("userId")
	sessionIdStr := builder.CreateString("sessionId")
	ipAddressStr := builder.CreateString("ipAddress")
	errorStr := builder.CreateString("error")

	key1 := builder.CreateString("key1")
	value1 := builder.CreateString("value1")
	events.TupleStart(builder)
	events.TupleAddKey(builder, key1)
	events.TupleAddValue(builder, value1)
	detail1 := events.TupleEnd(builder)

	key2 := builder.CreateString("key2")
	value2 := builder.CreateString("value2")
	events.TupleStart(builder)
	events.TupleAddKey(builder, key2)
	events.TupleAddValue(builder, value2)
	detail2 := events.TupleEnd(builder)

	events.EventStartDetailsVector(builder, 2)
	builder.PrependUOffsetT(detail1)
	builder.PrependUOffsetT(detail2)
	details := builder.EndVector(2)

	events.EventStart(builder)
	events.EventAddUid(builder, UID)
	events.EventAddTime(builder, time.Now().Unix())
	events.EventAddType(builder, 0)
	events.EventAddRealmId(builder, realmStr)
	events.EventAddClientId(builder, clientIdStr)
	events.EventAddUserId(builder, userIdStr)
	events.EventAddSessionId(builder, sessionIdStr)
	events.EventAddIpAddress(builder, ipAddressStr)
	events.EventAddError(builder, errorStr)
	events.EventAddDetails(builder, details)
	eventOffset := events.EventEnd(builder)
	builder.Finish(eventOffset)
	event := events.GetRootAsEvent(builder.FinishedBytes(), 0)

	var m = eventToMap(event)

	fmt.Print(m)
}

func createEvent(eventType int8) (*events.Event){
	return events.GetRootAsEvent(createEventBytes(eventType), 0)
}

func createEventBytes(eventType int8) ([]byte){
	builder := flatbuffers.NewBuilder(0)
	realmStr := builder.CreateString(REALM)
	events.EventStart(builder)
	events.EventAddUid(builder, UID)
	events.EventAddTime(builder, time.Now().Unix())
	events.EventAddType(builder, eventType)
	events.EventAddRealmId(builder, realmStr)
	eventOffset := events.EventEnd(builder)
	builder.Finish(eventOffset)
	return builder.FinishedBytes()
}

func createAdminEvent(operationType int8) (*events.AdminEvent){
	return events.GetRootAsAdminEvent(createAdminEventBytes(operationType), 0)
}

func createAdminEventBytes(operationType int8) ([]byte){
	builder := flatbuffers.NewBuilder(0)
	events.AdminEventStart(builder)
	events.AdminEventAddTime(builder, time.Now().Unix())
	events.AdminEventAddUid(builder, UID)
	events.AdminEventAddOperationType(builder, operationType)
	adminEventOffset := events.AdminEventEnd(builder)
	builder.Finish(adminEventOffset)
	return builder.FinishedBytes()
}

func getOperationTypeName(key int8) string{
	return events.EnumNamesOperationType[int(key)]
}