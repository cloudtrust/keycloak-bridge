package health

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// MakeHealthCheckHandler make an HTTP handler for an HealthCheck endpoint.
func MakeHealthCheckHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHealthCheckRequest,
		encodeHealthCheckReply,
		http_transport.ServerErrorEncoder(healthCheckErrorHandler),
	)
}

// decodeHealthCheckRequest decodes the health check request.
func decodeHealthCheckRequest(_ context.Context, r *http.Request) (rep interface{}, err error) {
	return nil, nil
}

// reply contains all health check reports.
type reply struct {
	Reports []healthCheck `json:"health checks"`
}

// healthCheck is the result of a single healthcheck.
type healthCheck struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

// encodeHealthCheckReply encodes the health check reply.
func encodeHealthCheckReply(_ context.Context, w http.ResponseWriter, rep interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var data, err = json.MarshalIndent(&rep, "", "  ")

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}

	return nil
}

// healthCheckErrorHandler encodes the health check reply when there is an error.
func healthCheckErrorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch err.Error() {
	case "rate limit exceeded":
		w.WriteHeader(http.StatusTooManyRequests)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}

	// Write error.
	var reply, _ = json.MarshalIndent(map[string]string{"error": err.Error()}, "", "  ")
	w.Write(reply)
}
