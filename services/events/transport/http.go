package transport

import (
	"encoding/base64"
	"net/http"
	"context"
	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"encoding/json"
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

type EventRequest struct {
	Type string
	Object []byte
}

func decodeKeycloakEventsReceiverRequest(_ context.Context, r *http.Request) (res interface{}, err error) {

	var request KeycloakEventReceiverRequest
	{
		var err error = json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			return EventRequest{}, err
		}
	}

	var bEvent []byte
	{
		var err error
		bEvent, err = base64.StdEncoding.DecodeString(request.Object)

		if err != nil {
			return EventRequest{}, err
		}
	}


	var objType string =request.Type
	{
		if !(objType == "AdminEvent" || objType == "Event"){
			var err ErrInvalidArgument
			err.InvalidParam = "type"
			return EventRequest{}, err
		}
	}

	// Check valid buffer (at least 4 bytes)
	if len(bEvent) < 4 {
		var err ErrInvalidArgument
		err.InvalidParam = "obj"
		return EventRequest{}, err
	}


	res = EventRequest {
		Type: objType,
		Object: bEvent,
	}

	return res, nil
}

func MakeReceiverHandler(e endpoint.Endpoint, log log.Logger) *httptransport.Server {
	return httptransport.NewServer(e,
		decodeKeycloakEventsReceiverRequest,
		encodeResponse,
		httptransport.ServerErrorEncoder(MakeErrorHandler(log)))
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.WriteHeader(http.StatusOK)
	return nil
}

func MakeErrorHandler(logger log.Logger) httptransport.ErrorEncoder {
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




