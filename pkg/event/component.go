package event

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=MuxComponent=MuxComponent,Component=Component,AdminComponent=AdminComponent github.com/cloudtrust/keycloak-bridge/pkg/event MuxComponent,Component,AdminComponent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
)

// MuxComponent is the Mux component interface.
type MuxComponent interface {
	Event(ctx context.Context, eventType string, obj []byte) error
}

type muxComponent struct {
	component      Component
	adminComponent AdminComponent
}

// NewMuxComponent returns a Mux component.
func NewMuxComponent(component Component, adminComponent AdminComponent) MuxComponent {
	return &muxComponent{
		component:      component,
		adminComponent: adminComponent,
	}
}

func (c *muxComponent) Event(ctx context.Context, eventType string, obj []byte) error {
	switch eventType {
	case "Event":
		var event = fb.GetRootAsEvent(obj, 0)
		return c.component.Event(ctx, event)
	case "AdminEvent":
		var adminEvent = fb.GetRootAsAdminEvent(obj, 0)
		return c.adminComponent.AdminEvent(ctx, adminEvent)
	default:
		return ErrInvalidArgument{InvalidParam: "Type"}
	}
}

// Component is the event component interface.
type Component interface {
	Event(ctx context.Context, event *fb.Event) error
}

type component struct {
	fStdEvent []FuncEvent
	fErrEvent []FuncEvent
}

// NewComponent returns an event component.
func NewComponent(modulesToCallForStandardEvent []FuncEvent,
	modulesToCallForErrorEvent []FuncEvent) Component {
	return &component{
		fStdEvent: modulesToCallForStandardEvent,
		fErrEvent: modulesToCallForErrorEvent,
	}
}

func (c *component) Event(ctx context.Context, event *fb.Event) error {
	var eventType = int8(event.Type())
	var eventTypeName = fb.EnumNamesEventType[eventType]
	var eventMap = eventToMap(event)

	if strings.HasSuffix(eventTypeName, "_ERROR") {
		return apply(ctx, c.fErrEvent, eventMap)
	}

	return apply(ctx, c.fStdEvent, eventMap)
}

// AdminComponent is the admin event component interface.
type AdminComponent interface {
	AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error
}

// FuncEvent is the function to call for a given event.
type FuncEvent = func(context.Context, map[string]string) error

type adminComponent struct {
	modulesToCallForCreate []FuncEvent
	modulesToCallForUpdate []FuncEvent
	modulesToCallForDelete []FuncEvent
	modulesToCallForAction []FuncEvent
}

// NewAdminComponent returns an admin event component.
func NewAdminComponent(modulesToCallForCreate []FuncEvent,
	modulesToCallForUpdate []FuncEvent,
	modulesToCallForDelete []FuncEvent,
	modulesToCallForAction []FuncEvent) AdminComponent {
	return &adminComponent{
		modulesToCallForCreate: modulesToCallForCreate,
		modulesToCallForUpdate: modulesToCallForUpdate,
		modulesToCallForDelete: modulesToCallForDelete,
		modulesToCallForAction: modulesToCallForAction,
	}
}

func (c *adminComponent) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error {
	var adminEventMap = adminEventToMap(adminEvent)
	switch operationType := adminEvent.OperationType(); operationType {
	case fb.OperationTypeCREATE:
		return apply(ctx, c.modulesToCallForCreate, adminEventMap)
	case fb.OperationTypeUPDATE:
		return apply(ctx, c.modulesToCallForUpdate, adminEventMap)
	case fb.OperationTypeDELETE:
		return apply(ctx, c.modulesToCallForDelete, adminEventMap)
	case fb.OperationTypeACTION:
		return apply(ctx, c.modulesToCallForAction, adminEventMap)
	default:
		return ErrInvalidArgument{InvalidParam: "OperationType"}
	}
}

func addCTtypeToEvent(event map[string]string) map[string]string {
	// add the CTEventType

	//ACCOUNT_CREATED
	if event["operationType"] == "CREATE" {
		// check if the resourcePath starts with prefix users
		if strings.HasPrefix(event["resourcePath"], "users") {
			event["ct_event_type"] = "ACCOUNT_CREATED"
			return event
		}
	}
	//ACTIVATION_EMAIL_SENT
	if event["operationType"] == "ACTION" {
		// check if the resourcePath ends with sufix send-verify-email
		if strings.HasSuffix(event["resourcePath"], "send-verify-email") {
			event["ct_event_type"] = "ACTIVATION_EMAIL_SENT"
			return event
		}
	}
	//EMAIL_CONFIRMED
	if event["type"] == "CUSTOM_REQUIRED_ACTION" {
		eventDetails := []byte(event["details"])
		var f map[string]string
		_ = json.Unmarshal(eventDetails, &f)

		if f["custom_required_action"] == "VERIFY_EMAIL" {
			event["ct_event_type"] = "EMAIL_CONFIRMED"
			return event
		}
	}
	//CONFIRM_EMAIL_EXPIRED
	if event["type"] == "EXECUTE_ACTION_TOKEN_ERROR" && event["error"] == "expired_code" {
		event["ct_event_type"] = "CONFIRM_EMAIL_EXPIRED"
		return event
	}
	//PASSWORD_RESET
	if event["type"] == "UPDATE_PASSWORD" {
		eventDetails := []byte(event["details"])
		var f map[string]string
		_ = json.Unmarshal(eventDetails, &f)

		if f["custom_required_action"] == "sms-password-set" {
			event["ct_event_type"] = "PASSWORD_RESET"
			return event
		}
	}
	//LOGON_OK
	if event["type"] == "LOGIN" {
		event["ct_event_type"] = "LOGON_OK"
		return event
	}
	//LOGON_ERROR
	if event["type"] == "LOGIN_ERROR" {
		event["ct_event_type"] = "LOGON_ERROR"
		return event
	}
	//LOGOUT
	if event["type"] == "LOGOUT" {
		event["ct_event_type"] = "LOGOUT"
		return event
	}

	// for all those events that don't have set the ct_event_type, we assign an empty ct_event_type
	if _, ok := event["ct_event_type"]; !ok {
		event["ct_event_type"] = ""
	}

	return event
}

func adminEventToMap(adminEvent *fb.AdminEvent) map[string]string {
	var adminEventMap = make(map[string]string)
	adminEventMap["uid"] = fmt.Sprint(adminEvent.Uid())

	time := epochMilliToTime(adminEvent.Time())
	adminEventMap["time"] = time.Format("2006-01-02T15:04:05.000Z")

	adminEventMap["realmId"] = string(adminEvent.RealmId())

	authDetails := adminEvent.AuthDetails(nil)
	var authDetailsMap map[string]string
	authDetailsMap = make(map[string]string)
	authDetailsMap["clientId"] = string(authDetails.ClientId())
	authDetailsMap["ipAddress"] = string(authDetails.IpAddress())
	authDetailsMap["realmId"] = string(authDetails.RealmId())
	authDetailsMap["userId"] = string(authDetails.UserId())

	// BE AWARE: error is not treated
	authDetailsJson, _ := json.Marshal(authDetailsMap)
	adminEventMap["authDetails"] = string(authDetailsJson)

	adminEventMap["resourceType"] = string(adminEvent.ResourceType())
	adminEventMap["operationType"] = fb.EnumNamesOperationType[int8(adminEvent.OperationType())]
	adminEventMap["resourcePath"] = string(adminEvent.ResourcePath())
	adminEventMap["representation"] = string(adminEvent.Representation())
	adminEventMap["error"] = string(adminEvent.Error())
	//all the admin events have, by default, the ct_event_type set to admin
	adminEventMap["ct_event_type"] = "ADMIN"

	//set the correct ct_event_type for actions like create_account, etc.
	adminEventMap = addCTtypeToEvent(adminEventMap)

	return adminEventMap
}

func eventToMap(event *fb.Event) map[string]string {
	var eventMap = make(map[string]string)
	eventMap["uid"] = fmt.Sprint(event.Uid())

	time := epochMilliToTime(event.Time())
	eventMap["time"] = time.Format("2006-01-02T15:04:05.000Z")

	eventMap["type"] = fb.EnumNamesEventType[int8(event.Type())]
	eventMap["realmId"] = string(event.RealmId())
	eventMap["clientId"] = string(event.ClientId())
	eventMap["userId"] = string(event.UserId())
	eventMap["sessionId"] = string(event.SessionId())
	eventMap["ipAddress"] = string(event.IpAddress())
	eventMap["error"] = string(event.Error())

	var detailsMap map[string]string
	detailsMap = make(map[string]string)
	var detailsLength = event.DetailsLength()
	for i := 0; i < detailsLength; i++ {
		var tuple = new(fb.Tuple)
		event.Details(tuple, i)
		if string(tuple.Key()) == "ct_event_type" {
			eventMap[string(tuple.Key())] = string(tuple.Value())
		} else {
			detailsMap[string(tuple.Key())] = string(tuple.Value())
		}
	}

	// BE AWARE: error is not treated
	detailsJson, _ := json.Marshal(detailsMap)
	eventMap["details"] = string(detailsJson)

	eventMap = addCTtypeToEvent(eventMap)

	return eventMap
}

func apply(ctx context.Context, fs [](FuncEvent), param map[string]string) error {
	var errors = make(chan error, len(fs))
	var wg sync.WaitGroup

	// Wait for all fs.
	wg.Add(len(fs))

	for _, f := range fs {
		go func(wg *sync.WaitGroup, f FuncEvent) {
			defer wg.Done()

			var err = f(ctx, param)
			if err != nil {
				errors <- err
			}
		}(&wg, f)
	}

	wg.Wait()

	select {
	case err, ok := <-errors:
		if ok {
			return err
		}
	default:
		return nil
	}
	return nil
}

func epochMilliToTime(milli int64) time.Time {
	return time.Unix(0, milli*1000000)
}
