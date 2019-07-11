package event

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/pkg/errors"
)

// MakeHTTPEventHandler makes a HTTP handler for the event endpoint.
func MakeHTTPEventHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHTTPRequest,
		encodeHTTPReply,
		http_transport.ServerErrorEncoder(errorHandler),
		http_transport.ServerBefore(fetchHTTPCorrelationID),
	)
}

// fetchHTTPCorrelationID reads the correlation ID from the http header "X-Correlation-ID".
// If the ID is not zero, we put it in the context.
func fetchHTTPCorrelationID(ctx context.Context, req *http.Request) context.Context {
	var correlationID = req.Header.Get("X-Correlation-ID")
	if correlationID != "" {
		ctx = context.WithValue(ctx, cs.CtContextCorrelationID, correlationID)
	}
	return ctx
}

// KeycloakRequest is the Request for KeycloakEventReceiver endpoint.
type KeycloakRequest struct {
	Type   string
	Object string `json:"Obj"`
}

// Request has the fields Type and Object.
type Request struct {
	Type   string
	Object []byte
}

// decodeHTTPRequest decodes the http event request.
func decodeHTTPRequest(_ context.Context, r *http.Request) (res interface{}, err error) {
	var request KeycloakRequest
	{
		var err = json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			return nil, errors.Wrap(err, "cannotDecodeJSONRequest")
		}
	}

	var bEvent []byte
	{
		var err error
		bEvent, err = base64.StdEncoding.DecodeString(request.Object)

		if err != nil {
			return nil, errors.Wrap(err, "cannotDecodeBase64ObjectFromRequest")
		}
	}

	var objType = request.Type
	{
		if !(objType == "AdminEvent" || objType == "Event") {
			var err = ErrInvalidArgument{InvalidParam: "type"}
			return nil, errors.Wrap(err, "cannotDecodeBase64ObjectFromRequest")
		}
	}

	// Check valid buffer (at least 4 bytes)
	if len(bEvent) < 4 {
		var err = ErrInvalidArgument{InvalidParam: "obj"}
		return nil, errors.Wrap(err, "invalidFlatbufferLength")
	}

	return Request{
		Type:   objType,
		Object: bEvent,
	}, nil
}

// encodeHTTPReply encodes the http event reply.
func encodeHTTPReply(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.WriteHeader(http.StatusOK)
	return nil
}

// ErrInvalidArgument is returned when one or more arguments are invalid.
type ErrInvalidArgument struct {
	InvalidParam string
}

func (e ErrInvalidArgument) Error() string {
	return fmt.Sprintf("invalidArgument.%s", e.InvalidParam)
}

// errorHandler encodes the reply when there is an error.
func errorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch errors.Cause(err).(type) {
	case ErrInvalidArgument:
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Write([]byte(ComponentName + "." + err.Error()))
}
