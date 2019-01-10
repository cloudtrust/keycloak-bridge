package event

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
	"github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
)

func TestMuxComponent(t *testing.T) {
	var ch = make(chan string, 1)

	var fnEvent = func(ctx context.Context, eventMap map[string]string) error {
		ch <- "Event"
		return nil
	}

	var fnAdminEvent = func(ctx context.Context, eventMap map[string]string) error {
		ch <- "AdminEvent"
		return nil
	}

	var tEvent = []FuncEvent{fnEvent}
	var tAdminEvent = []FuncEvent{fnAdminEvent}

	var eventComponent = NewComponent(tEvent, tEvent)
	var adminEventService = NewAdminComponent(tAdminEvent, tAdminEvent, tAdminEvent, tAdminEvent)

	var muxComponent = NewMuxComponent(eventComponent, adminEventService)

	var event = createEventBytes(fb.EventTypeCLIENT_DELETE, 1234, "realm")
	var err = muxComponent.Event(context.Background(), "Event", event)
	assert.Equal(t, "Event", <-ch)
	assert.Nil(t, err)

	var adminEvent = createAdminEventBytes(fb.OperationTypeDELETE, 1234)
	var err2 = muxComponent.Event(context.Background(), "AdminEvent", adminEvent)
	assert.Equal(t, "AdminEvent", <-ch)
	assert.Nil(t, err2)
}
func TestComponent(t *testing.T) {
	var eventComponent Component
	{
		var fnStd = func(ctx context.Context, eventMap map[string]string) error {
			return nil
		}

		var fnErr = func(ctx context.Context, eventMap map[string]string) error {
			return errors.New("Failed")
		}

		var tStd = []FuncEvent{fnStd}
		var tErr = []FuncEvent{fnErr}
		eventComponent = NewComponent(tStd, tErr)
	}

	{
		var eventStd = createEvent(fb.EventTypeCLIENT_DELETE, 1234, "realm")
		var err = eventComponent.Event(nil, eventStd)
		assert.Nil(t, err)
	}

	{
		var eventErr = createEvent(fb.EventTypeCLIENT_DELETE_ERROR, 1234, "realm")
		var err = eventComponent.Event(nil, eventErr)
		assert.NotNil(t, err)
	}
}
func TestAdminComponent(t *testing.T) {
	var adminEventComponent AdminComponent
	var ch = make(chan string, 1)
	{
		var fnCreate = func(ctx context.Context, eventMap map[string]string) error {
			ch <- "CREATE"
			return nil
		}

		var fnUpdate = func(ctx context.Context, eventMap map[string]string) error {
			ch <- "UPDATE"
			return nil
		}

		var fnDelete = func(ctx context.Context, eventMap map[string]string) error {
			ch <- "DELETE"
			return nil
		}

		var fnAction = func(ctx context.Context, eventMap map[string]string) error {
			ch <- "ACTION"
			return nil
		}

		var tCreate = [](FuncEvent){fnCreate}
		var tUpdate = [](FuncEvent){fnUpdate}
		var tDelete = [](FuncEvent){fnDelete}
		var tAction = [](FuncEvent){fnAction}
		adminEventComponent = NewAdminComponent(tCreate, tUpdate, tDelete, tAction)
	}

	var fn = func(operationType int8) {
		var adminEvt *fb.AdminEvent = createAdminEvent(fb.OperationTypeCREATE, 1234)
		var err = adminEventComponent.AdminEvent(nil, adminEvt)

		assert.Equal(t, getOpertimech)
		assert.Nil(t, err)
	}

	var operationTypes = [4]inttime
		fb.OperationTypeUPDATE,time
		fb.OperationTypeDELETE,
		fb.OperationTypeACTION}

	for _, element := range operationTypes {
		fn(element)
	}
}

func TestEventToMap(t *testing.T) {
	var uid int64 = 1234
	var epoch = int64(1547127600485)
	var etype int8
	var realmID = "realm"
	var clientID = "client"
	var userID = "user"
	var sessionID = "session"
	var ipAddr = "ipAddress"
	var error = "error"

	var event *fb.Event
	{
		var builder = flatbuffers.NewBuilder(0)

		var realm = builder.CreateString(realmID)
		var clientID = builder.CreateString(clientID)
		var userID = builder.CreateString(userID)
		var sessionID = builder.CreateString(sessionID)
		var ipAddress = builder.CreateString(ipAddr)
		var error = builder.CreateString(error)

		var key1 = builder.CreateString("key1")
		var value1 = builder.CreateString("value1")
		fb.TupleStart(builder)
		fb.TupleAddKey(builder, key1)
		fb.TupleAddValue(builder, value1)
		var detail1 = fb.TupleEnd(builder)

		var key2 = builder.CreateString("key2")
		var value2 = builder.CreateString("value2")
		fb.TupleStart(builder)
		fb.TupleAddKey(builder, key2)
		fb.TupleAddValue(builder, value2)
		var detail2 = fb.TupleEnd(builder)

		fb.EventStartDetailsVector(builder, 2)
		builder.PrependUOffsetT(detail1)
		builder.PrependUOffsetT(detail2)
		var details = builder.EndVector(2)

		fb.EventStart(builder)
		fb.EventAddUid(builder, uid)
		fb.EventAddTime(builder, epoch)
		fb.EventAddType(builder, etype)
		fb.EventAddRealmId(builder, realm)
		fb.EventAddClientId(builder, clientID)
		fb.EventAddUserId(builder, userID)
		fb.EventAddSessionId(builder, sessionID)
		fb.EventAddIpAddress(builder, ipAddress)
		fb.EventAddError(builder, error)
		fb.EventAddDetails(builder, details)
		var eventOffset = fb.EventEnd(builder)
		builder.Finish(eventOffset)
		event = fb.GetRootAsEvent(builder.FinishedBytes(), 0)
	}

	var m = eventToMap(event)
	assert.Equal(t, strconv.FormatInt(uid, 10), m["uid"])
	assert.Equal(t, time.Unix(0, epoch*1000000).Format("2006-01-02T15:04:05.000Z"), m["time"])
	assert.Equal(t, fb.EnumNamesEventType[int8(etype)], m["type"])
	assert.Equal(t, realmID, m["realmId"])
	assert.Equal(t, clientID, m["clientId"])
	assert.Equal(t, userID, m["userId"])
	assert.Equal(t, sessionID, m["sessionId"])
	assert.Equal(t, ipAddr, m["ipAddress"])
	assert.Equal(t, error, m["error"])

}

func createEvent(eventType int8, uid int64, realm string) *fb.Event {
	return fb.GetRootAsEvent(createEventBytes(eventType, uid, realm), 0)
}

func createEventBytes(eventType int8, uid int64, realm string) []byte {
	var builder = flatbuffers.NewBuilder(0)
	var realmStr = builder.CreateString(realm)
	fb.EventStart(builder)
	fb.EventAddUid(builder, uid)
	fb.EventAddTime(builder, time.Now().Unix())
	fb.EventAddType(builder, eventType)
	fb.EventAddRealmId(builder, realmStr)
	var eventOffset = fb.EventEnd(builder)
	builder.Finish(eventOffset)
	return builder.FinishedBytes()
}

func createAdminEvent(operationType int8, uid int64) *fb.AdminEvent {
	return fb.GetRootAsAdminEvent(createAdminEventBytes(operationType, uid), 0)
}

func createAdminEventBytes(operationType int8, uid int64) []byte {
	var builder = flatbuffers.NewBuilder(0)
	fb.AdminEventStart(builder)
	fb.AdminEventAddTime(builder, time.Now().Unix())
	fb.AdminEventAddUid(builder, uid)
	fb.AdminEventAddOperationType(builder, operationType)
	var adminEventOffset = fb.AdminEventEnd(builder)
	builder.Finish(adminEventOffset)
	return builder.FinishedBytes()
}

func getOperationTypeName(key int8) string {
	return fb.EnumNamesOperationType[int8(key)]
}
