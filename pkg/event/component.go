package event

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
)

var (
	// ComponentName is the name of the component.
	ComponentName = "keycloak-bridge"
)

const (
	timeFormat = "2006-01-02 15:04:05.000"
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
	// add the ct_event_type

	addInfo := []byte(event[database.CtEventAdditionalInfo])
	var f map[string]string
	_ = json.Unmarshal(addInfo, &f)

	switch opType := event[database.CtEventKcOperationType]; opType {
	case "CREATE":
		//ACCOUNT_CREATED
		// check if the resourcePath starts with prefix users
		if strings.HasPrefix(f["resource_path"], "users") {
			event[database.CtEventType] = "ACCOUNT_CREATED"
			return event
		}
	case "ACTION":
		//ACTIVATION_EMAIL_SENT
		// check if the resourcePath ends with suffix send-verify-email
		if strings.HasSuffix(f["resource_path"], "send-verify-email") {
			event[database.CtEventType] = "ACTIVATION_EMAIL_SENT"
			return event
		}
	default:
		// Nothing to do here
	}

	switch t := event[database.CtEventKcEventType]; t {
	case "CUSTOM_REQUIRED_ACTION":
		//EMAIL_CONFIRMED
		if f["custom_required_action"] == "VERIFY_EMAIL" {
			event[database.CtEventType] = "EMAIL_CONFIRMED"
			return event
		}
	case "EXECUTE_ACTION_TOKEN_ERROR":
		//CONFIRM_EMAIL_EXPIRED
		if f["error"] == "expired_code" {
			event[database.CtEventType] = "CONFIRM_EMAIL_EXPIRED"
			return event
		}
	case "UPDATE_PASSWORD":
		//PASSWORD_RESET
		if f["custom_required_action"] == "sms-password-set" {
			event[database.CtEventType] = "PASSWORD_RESET"
			return event
		}
	case "LOGIN":
		//LOGON_OK
		event[database.CtEventType] = "LOGON_OK"
		return event

	case "LOGIN_ERROR":
		//LOGON_ERROR
		event[database.CtEventType] = "LOGON_ERROR"
		return event
	case "LOGOUT":
		//LOGOUT
		event[database.CtEventType] = "LOGOUT"
		return event
	default:
		// Nothing to do here
	}

	// for all those events that don't have set the ct_event_type, we assign an empty ct_event_type
	if _, ok := event[database.CtEventType]; !ok {
		event[database.CtEventType] = ""
	}

	return event
}

func adminEventToMap(adminEvent *fb.AdminEvent) map[string]string {
	var adminEventMap = make(map[string]string)
	var addInfo = make(map[string]string)

	addInfo["uid"] = fmt.Sprint(adminEvent.Uid())

	time := epochMilliToTime(adminEvent.Time()).UTC()
	adminEventMap[database.CtEventAuditTime] = time.Format(timeFormat) //audit_time

	adminEventMap[database.CtEventRealmName] = string(adminEvent.RealmId()) //realm_name
	adminEventMap[database.CtEventOrigin] = "keycloak"                      //origin

	authDetails := adminEvent.AuthDetails(nil)

	adminEventMap[database.CtEventClientID] = string(authDetails.ClientId()) //client_id
	addInfo["ip_address"] = string(authDetails.IpAddress())
	adminEventMap[database.CtEventAgentRealmName] = string(authDetails.RealmId()) // agent_realm_name
	adminEventMap[database.CtEventAgentUserID] = string(authDetails.UserId())     //agent_user_id

	addInfo["resource_type"] = string(adminEvent.ResourceType())
	adminEventMap[database.CtEventKcOperationType] = fb.EnumNamesOperationType[int8(adminEvent.OperationType())] //kc_operation_type
	addInfo["resource_path"] = string(adminEvent.ResourcePath())
	reg := regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)
	if strings.HasPrefix(addInfo["resource_path"], "users") {
		adminEventMap[database.CtEventUserID] = string(reg.Find([]byte(addInfo["resource_path"]))) //user_id
	}

	addInfo["representation"] = string(adminEvent.Representation())
	addInfo["error"] = string(adminEvent.Error())
	//all the admin events have, by default, the ct_event_type set to admin
	adminEventMap[database.CtEventType] = "ADMIN"

	// BE AWARE: error is not treated
	infoJSON, _ := json.Marshal(addInfo)
	adminEventMap[database.CtEventAdditionalInfo] = string(infoJSON)

	//set the correct ct_event_type for actions like create_account, etc.
	adminEventMap = addCTtypeToEvent(adminEventMap)

	return adminEventMap
}

func eventToMap(event *fb.Event) map[string]string {
	var eventMap = make(map[string]string)
	var addInfo = make(map[string]string)
	// if an event has the ct_event_type set already, the flag avoids rewriting it
	var doNotSetCTEventType = false

	addInfo["uid"] = fmt.Sprint(event.Uid())

	time := epochMilliToTime(event.Time()).UTC()
	eventMap[database.CtEventAuditTime] = time.Format(timeFormat) //audit_time

	eventMap[database.CtEventKcEventType] = fb.EnumNamesEventType[int8(event.Type())] // kc_event_type
	eventMap[database.CtEventRealmName] = string(event.RealmId())                     //realm_name
	eventMap[database.CtEventClientID] = string(event.ClientId())                     //client_id
	eventMap[database.CtEventAgentUserID] = string(event.UserId())                    //agent_user_id
	eventMap[database.CtEventUserID] = string(event.UserId())                         //user_id
	//Note: we make the assumption that the agent and the user are the same in the case of the events that are not admin events

	addInfo["session_id"] = string(event.SessionId())
	addInfo["ip_address"] = string(event.IpAddress())
	addInfo["error"] = string(event.Error())
	eventMap[database.CtEventOrigin] = "keycloak" //origin

	var detailsLength = event.DetailsLength()
	for i := 0; i < detailsLength; i++ {
		var tuple = new(fb.Tuple)
		event.Details(tuple, i)
		if string(tuple.Key()) == database.CtEventType {
			eventMap[string(tuple.Key())] = string(tuple.Value())
			doNotSetCTEventType = true
		} else {
			if string(tuple.Key()) == database.CtEventUsername {
				eventMap[database.CtEventAgentUsername] = string(tuple.Value()) //agent_username
				eventMap[string(tuple.Key())] = string(tuple.Value())           //username
			} else {
				addInfo[string(tuple.Key())] = string(tuple.Value())
			}

		}
	}

	// BE AWARE: error is not treated
	infoJSON, _ := json.Marshal(addInfo)
	eventMap[database.CtEventAdditionalInfo] = string(infoJSON)

	if !doNotSetCTEventType {
		eventMap = addCTtypeToEvent(eventMap)
	}

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
