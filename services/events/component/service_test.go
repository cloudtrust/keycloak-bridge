package components

import (
	"errors"
	"fmt"
	"testing"
	"time"

	events "github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/fb"
	"github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
	//"github.com/go-kit/kit/log"
	//events_console "github.com/cloudtrust/keycloak-bridge/services/events/modules/console"
	//"os"
	"golang.org/x/net/context"
)

var UID int64 = 1234
var REALM = "realm"

func TestEventComponents_NewEventService(t *testing.T) {
	var eventService EventService
	{
		var fnStd = func(eventMap map[string]string) error {
			return nil
		}

		var fnErr = func(eventMap map[string]string) error {
			return errors.New("Failed")
		}

		var tStd = [](func(map[string]string) error){fnStd}
		var tErr = [](func(map[string]string) error){fnErr}
		eventService = NewEventService(tStd, tErr)
	}

	{
		var eventStd = createEvent(events.EventTypeCLIENT_DELETE)
		var res, err = eventService.Event(nil, eventStd)
		assert.Equal(t, "ok", res)
		assert.Nil(t, err)
	}

	{
		var eventErr = createEvent(events.EventTypeCLIENT_DELETE_ERROR)
		var res, err = eventService.Event(nil, eventErr)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestEventComponents_NewAdminEventService(t *testing.T) {
	var adminEventService AdminEventService
	var ch = make(chan string, 1)
	{
		var fnCreate = func(eventMap map[string]string) error {
			ch <- "CREATE"
			return nil
		}

		var fnUpdate = func(eventMap map[string]string) error {
			ch <- "UPDATE"
			return nil
		}

		var fnDelete = func(eventMap map[string]string) error {
			ch <- "DELETE"
			return nil
		}

		var fnAction = func(eventMap map[string]string) error {
			ch <- "ACTION"
			return nil
		}

		var tCreate = [](func(map[string]string) error){fnCreate}
		var tUpdate = [](func(map[string]string) error){fnUpdate}
		var tDelete = [](func(map[string]string) error){fnDelete}
		var tAction = [](func(map[string]string) error){fnAction}
		adminEventService = NewAdminEventService(tCreate, tUpdate, tDelete, tAction)
	}

	var fn = func(operationType int8) {
		var adminEvt *events.AdminEvent = createAdminEvent(events.OperationTypeCREATE)
		var _, err = adminEventService.AdminEvent(nil, adminEvt)

		assert.Equal(t, getOperationTypeName(events.OperationTypeCREATE), <-ch)
		assert.Nil(t, err)
	}

	var operationTypes = [4]int8{events.OperationTypeCREATE,
		events.OperationTypeUPDATE,
		events.OperationTypeDELETE,
		events.OperationTypeACTION}

	for _, element := range operationTypes {
		fn(element)
	}
}

func TestEventComponents_NewMuxService(t *testing.T) {

	var muxService MuxService
	var ch = make(chan string, 1)
	{
		var fnEvent = func(eventMap map[string]string) error {
			ch <- "Event"
			return nil
		}

		var fnAdminEvent = func(eventMap map[string]string) error {
			ch <- "AdminEvent"
			return nil
		}

		var tEvent = [](func(map[string]string) error){fnEvent}
		var tAdminEvent = [](func(map[string]string) error){fnAdminEvent}

		var eventService = NewEventService(tEvent, tEvent)
		var adminEventService = NewAdminEventService(tAdminEvent, tAdminEvent, tAdminEvent, tAdminEvent)

		muxService = NewMuxService(eventService, adminEventService)
	}

	{
		var event = createEventBytes(events.EventTypeCLIENT_DELETE)
		var _, err = muxService.Event(context.Background(), "Event", event)
		assert.Equal(t, "Event", <-ch)
		assert.Nil(t, err)
	}

	{
		var adminEvent = createAdminEventBytes(events.OperationTypeDELETE)
		var _, err = muxService.Event(context.Background(), "AdminEvent", adminEvent)
		assert.Equal(t, "AdminEvent", <-ch)
		assert.Nil(t, err)
	}
}

func TestEventComponents_eventToMap(t *testing.T) {

	var builder = flatbuffers.NewBuilder(0)

	var realmStr = builder.CreateString(REALM)
	var clientIDStr = builder.CreateString("clientId")
	var userIDStr = builder.CreateString("userId")
	var sessionIDStr = builder.CreateString("sessionId")
	var ipAddressStr = builder.CreateString("ipAddress")
	var errorStr = builder.CreateString("error")

	var key1 = builder.CreateString("key1")
	var value1 = builder.CreateString("value1")
	events.TupleStart(builder)
	events.TupleAddKey(builder, key1)
	events.TupleAddValue(builder, value1)
	var detail1 = events.TupleEnd(builder)

	var key2 = builder.CreateString("key2")
	var value2 = builder.CreateString("value2")
	events.TupleStart(builder)
	events.TupleAddKey(builder, key2)
	events.TupleAddValue(builder, value2)
	var detail2 = events.TupleEnd(builder)

	events.EventStartDetailsVector(builder, 2)
	builder.PrependUOffsetT(detail1)
	builder.PrependUOffsetT(detail2)
	var details = builder.EndVector(2)

	events.EventStart(builder)
	events.EventAddUid(builder, UID)
	events.EventAddTime(builder, time.Now().Unix())
	events.EventAddType(builder, 0)
	events.EventAddRealmId(builder, realmStr)
	events.EventAddClientId(builder, clientIDStr)
	events.EventAddUserId(builder, userIDStr)
	events.EventAddSessionId(builder, sessionIDStr)
	events.EventAddIpAddress(builder, ipAddressStr)
	events.EventAddError(builder, errorStr)
	events.EventAddDetails(builder, details)
	var eventOffset = events.EventEnd(builder)
	builder.Finish(eventOffset)
	var event = events.GetRootAsEvent(builder.FinishedBytes(), 0)

	var m = eventToMap(event)

	fmt.Print(m)
}

func createEvent(eventType int8) *events.Event {
	return events.GetRootAsEvent(createEventBytes(eventType), 0)
}

func createEventBytes(eventType int8) []byte {
	var builder = flatbuffers.NewBuilder(0)
	var realmStr = builder.CreateString(REALM)
	events.EventStart(builder)
	events.EventAddUid(builder, UID)
	events.EventAddTime(builder, time.Now().Unix())
	events.EventAddType(builder, eventType)
	events.EventAddRealmId(builder, realmStr)
	var eventOffset = events.EventEnd(builder)
	builder.Finish(eventOffset)
	return builder.FinishedBytes()
}

func createAdminEvent(operationType int8) *events.AdminEvent {
	return events.GetRootAsAdminEvent(createAdminEventBytes(operationType), 0)
}

func createAdminEventBytes(operationType int8) []byte {
	var builder = flatbuffers.NewBuilder(0)
	events.AdminEventStart(builder)
	events.AdminEventAddTime(builder, time.Now().Unix())
	events.AdminEventAddUid(builder, UID)
	events.AdminEventAddOperationType(builder, operationType)
	var adminEventOffset = events.AdminEventEnd(builder)
	builder.Finish(adminEventOffset)
	return builder.FinishedBytes()
}

func getOperationTypeName(key int8) string {
	return events.EnumNamesOperationType[int(key)]
}
