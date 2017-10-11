package transport

import (
	"encoding/base64"
	"net/http"
	"context"
	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"encoding/json"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
	"github.com/go-kit/kit/log"
)

// ErrInvalidArgument is returned when one or more arguments are invalid.
type ErrInvalidArgument struct{
	InvalidParam string
}

func (e ErrInvalidArgument) Error() string{
	return "Invalid argument: " + e.InvalidParam
}

/*
Request for KeycloakEventReceiver endpoint
 */
type KeycloakEventReceiverRequest struct {
	Type string
	Object string
}


func MakeReceiverHandler(e endpoint.Endpoint, log log.Logger) *httptransport.Server{
	return httptransport.NewServer(e,
		decodeKeycloakEventsReceiverRequest,
		encodeResponse,
		httptransport.ServerErrorEncoder(MakeErrorHandler(log)))
}

func decodeKeycloakEventsReceiverRequest(_ context.Context, r *http.Request) (res interface{}, err error) {

	var request KeycloakEventReceiverRequest
	{
		var err error
		if err = json.NewDecoder(r.Body).Decode(&request); err != nil {
			return nil, err
		}
	}

	var bEvent []byte
	{
		var err error
		bEvent, err = base64.StdEncoding.DecodeString(request.Object)

		if err != nil {
			return nil, err
		}
	}

	switch objType:=request.Type; objType {
	case "AdminEvent":
		var adminEvent *events.AdminEvent
		adminEvent= events.GetRootAsAdminEvent(bEvent, 0)
		return *adminEvent, nil
	case "Event":
		var event *events.Event
		event= events.GetRootAsEvent(bEvent, 0)
		return *event, nil
	default:
		var err ErrInvalidArgument
		err.InvalidParam = "Type"
		return nil, err
	}
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.WriteHeader(http.StatusOK)
	return nil
}

func MakeErrorHandler(logger log.Logger) httptransport.ErrorEncoder{
	var errorHandler httptransport.ErrorEncoder
	errorHandler = func (ctx context.Context, err error, w http.ResponseWriter){
		logger.Log(err.Error())

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch err {
		case ErrInvalidArgument{}:
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
	}
	return errorHandler
}




