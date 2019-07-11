package export

import (
	"context"
	"encoding/json"
	"net/http"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/pkg/errors"
)

// MakeHTTPExportHandler makes a HTTP handler for the export endpoint.
func MakeHTTPExportHandler(e endpoint.Endpoint) *http_transport.Server {
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

// decodeHTTPRequest decodes the http event request.
func decodeHTTPRequest(_ context.Context, _ *http.Request) (res interface{}, err error) {
	return nil, nil
}

// encodeHTTPReply encodes the http event reply.
func encodeHTTPReply(_ context.Context, w http.ResponseWriter, res interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var reply = res.(map[string]interface{})
	var data, err = json.MarshalIndent(reply, "", "  ")
	if err != nil {
		return errors.Wrap(err, "cannotMarshalResponse")
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return nil
}

// errorHandler encodes the reply when there is an error.
func errorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(ComponentName + "." + err.Error()))
}
