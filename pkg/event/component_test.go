package event

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	"github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
)

func TestMuxComponent(t *testing.T) {
	var ch = make(chan string, 1)

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

	var eventComponent = NewComponent(tEvent, tEvent)
	var adminEventService = NewAdminComponent(tAdminEvent, tAdminEvent, tAdminEvent, tAdminEvent)

	var muxComponent MuxComponent = NewMuxComponent(eventComponent, adminEventService)

	var event = createEventBytes(fb.EventTypeCLIENT_DELETE, 1234, "realm")
	var _, err = muxComponent.Event(context.Background(), "Event", event)
	assert.Equal(t, "Event", <-ch)
	assert.Nil(t, err)

	var adminEvent = createAdminEventBytes(fb.OperationTypeDELETE, 1234)
	var _, err2 = muxComponent.Event(context.Background(), "AdminEvent", adminEvent)
	assert.Equal(t, "AdminEvent", <-ch)
	assert.Nil(t, err2)

}
func TestComponent(t *testing.T) {
	var eventComponent Component
	{
		var fnStd = func(eventMap map[string]string) error {
			return nil
		}

		var fnErr = func(eventMap map[string]string) error {
			return errors.New("Failed")
		}

		var tStd = [](func(map[string]string) error){fnStd}
		var tErr = [](func(map[string]string) error){fnErr}
		eventComponent = NewComponent(tStd, tErr)
	}

	{
		var eventStd = createEvent(fb.EventTypeCLIENT_DELETE, 1234, "realm")
		var res, err = eventComponent.Event(nil, eventStd)
		assert.Equal(t, "ok", res)
		assert.Nil(t, err)
	}

	{
		var eventErr = createEvent(fb.EventTypeCLIENT_DELETE_ERROR, 1234, "realm")
		var res, err = eventComponent.Event(nil, eventErr)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}
func TestAdminComponent(t *testing.T) {
	var adminEventComponent AdminComponent
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
		adminEventComponent = NewAdminComponent(tCreate, tUpdate, tDelete, tAction)
	}

	var fn = func(operationType int8) {
		var adminEvt *fb.AdminEvent = createAdminEvent(fb.OperationTypeCREATE, 1234)
		var _, err = adminEventComponent.AdminEvent(nil, adminEvt)

		assert.Equal(t, getOperationTypeName(fb.OperationTypeCREATE), <-ch)
		assert.Nil(t, err)
	}

	var operationTypes = [4]int8{fb.OperationTypeCREATE,
		fb.OperationTypeUPDATE,
		fb.OperationTypeDELETE,
		fb.OperationTypeACTION}

	for _, element := range operationTypes {
		fn(element)
	}
}

func TestEventToMap(t *testing.T) {
	var uid int64 = 1234
	var time = time.Now().Unix()
	var etype int8 = 0
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
		fb.EventAddTime(builder, time)
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
	assert.Equal(t, strconv.FormatInt(time, 10), m["time"])
	assert.Equal(t, fb.EnumNamesEventType[int(etype)], m["type"])
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
	return fb.EnumNamesOperationType[int(key)]
}

// Mock MuxComponent.
type mockMuxComponent struct {
	fail bool
}

func (c *mockMuxComponent) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	if c.fail {
		return "", fmt.Errorf("fail")
	}
	return "", nil
}

// Mock AdminComponent.
type mockAdminComponent struct {
	fail bool
}

func (c *mockAdminComponent) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) (interface{}, error) {
	if c.fail {
		return "", fmt.Errorf("fail")
	}
	return "", nil
}

// Mock Component.
type mockComponent struct {
	fail bool
}

func (c *mockComponent) Event(ctx context.Context, event *fb.Event) (interface{}, error) {
	if c.fail {
		return "", fmt.Errorf("fail")
	}
	return "", nil
}
