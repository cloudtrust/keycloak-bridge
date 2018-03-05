package health

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Reply contains all health check reports
type Reply struct {
	Reports []Check `json:"health checks"`
}

// Check is the result of a single healthcheck
type Check struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

// MakeHealthChecksHandler makes a HTTP handler for all health checks.
func MakeHealthChecksHandler(es Endpoints) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		var report = map[string]string{}

		// Make all tests
		report["influx"] = makeReport(es.InfluxHealthCheck)
		report["jaeger"] = makeReport(es.JaegerHealthCheck)
		report["redis"] = makeReport(es.RedisHealthCheck)
		report["sentry"] = makeReport(es.SentryHealthCheck)
		report["keycloak"] = makeReport(es.KeycloakHealthCheck)

		// Write report.
		var j, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(j)
		}
	}
}

func makeReport(e endpoint.Endpoint) string {
	var hr, err = e(context.Background(), nil)
	var reports = hr.(Reports)

	if err != nil {
		return KO.String()
	}
	return reportsStatus(reports)
}

// reportsStatus returs 'OK' if all tests passed.
func reportsStatus(reports Reports) string {
	for _, r := range reports.Reports {
		if r.Status != OK {
			return KO.String()
		}
	}
	return OK.String()
}

// MakeInfluxHealthCheckHandler makes a HTTP handler for the Influx HealthCheck endpoint.
func MakeInfluxHealthCheckHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHealthCheckRequest,
		encodeHealthCheckReply,
		http_transport.ServerErrorEncoder(healthCheckErrorHandler),
	)
}

// MakeJaegerHealthCheckHandler makes a HTTP handler for the Jaeger HealthCheck endpoint.
func MakeJaegerHealthCheckHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHealthCheckRequest,
		encodeHealthCheckReply,
		http_transport.ServerErrorEncoder(healthCheckErrorHandler),
	)
}

// MakeRedisHealthCheckHandler makes a HTTP handler for the Redis HealthCheck endpoint.
func MakeRedisHealthCheckHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHealthCheckRequest,
		encodeHealthCheckReply,
		http_transport.ServerErrorEncoder(healthCheckErrorHandler),
	)
}

// MakeSentryHealthCheckHandler makes a HTTP handler for the Sentry HealthCheck endpoint.
func MakeSentryHealthCheckHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHealthCheckRequest,
		encodeHealthCheckReply,
		http_transport.ServerErrorEncoder(healthCheckErrorHandler),
	)
}

// MakeKeycloakHealthCheckHandler makes a HTTP handler for the Keycloak HealthCheck endpoint.
func MakeKeycloakHealthCheckHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHealthCheckRequest,
		encodeHealthCheckReply,
		http_transport.ServerErrorEncoder(healthCheckErrorHandler),
	)
}

// decodeHealthCheckRequest decodes the health check request.
func decodeHealthCheckRequest(_ context.Context, r *http.Request) (res interface{}, err error) {
	return nil, nil
}

// encodeHealthCheckReply encodes the health check reply.
func encodeHealthCheckReply(_ context.Context, w http.ResponseWriter, res interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var reports = res.(Reports)
	var hr = Reply{}
	for _, r := range reports.Reports {
		hr.Reports = append(hr.Reports, Check{
			Name:     r.Name,
			Duration: r.Duration,
			Status:   r.Status.String(),
			Error:    r.Error,
		})
	}

	var d, err = json.MarshalIndent(hr, "", "  ")

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write(d)
	}

	return nil
}

// healthCheckErrorHandler encodes the health check reply when there is an error.
func healthCheckErrorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}
