package health

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

type HealthChecksReply struct {
	Reports []HealthCheck `json:"health checks"`
}

type HealthCheck struct {
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
		var influxReport HealthReports
		{
			var err error
			var x interface{}
			x, err = es.InfluxHealthCheck(context.Background(), nil)
			influxReport = x.(HealthReports)

			if err != nil {
				report["influx"] = KO.String()
			} else {
				report["influx"] = reportsStatus(influxReport)
			}
		}
		var jaegerReport HealthReports
		{
			var err error
			var x interface{}
			x, err = es.JaegerHealthCheck(context.Background(), nil)
			jaegerReport = x.(HealthReports)

			if err != nil {
				report["jaeger"] = KO.String()
			} else {
				report["jaeger"] = reportsStatus(jaegerReport)
			}
		}
		var redisReport HealthReports
		{
			var err error
			var x interface{}
			x, err = es.RedisHealthCheck(context.Background(), nil)
			redisReport = x.(HealthReports)

			if err != nil {
				report["redis"] = KO.String()
			} else {
				report["redis"] = reportsStatus(redisReport)
			}
		}
		var sentryReport HealthReports
		{
			var err error
			var x interface{}
			x, err = es.SentryHealthCheck(context.Background(), nil)
			sentryReport = x.(HealthReports)

			if err != nil {
				report["sentry"] = KO.String()
			} else {
				report["sentry"] = reportsStatus(sentryReport)
			}
		}
		var keycloakReport HealthReports
		{
			var err error
			var x interface{}
			x, err = es.KeycloakHealthCheck(context.Background(), nil)
			keycloakReport = x.(HealthReports)

			if err != nil {
				report["keycloak"] = KO.String()
			} else {
				report["keycloak"] = reportsStatus(keycloakReport)
			}
		}

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

// reportsStatus returs 'OK' if all tests passed.
func reportsStatus(reports HealthReports) string {
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

	var reports = res.(HealthReports)
	var hr = HealthChecksReply{}
	for _, r := range reports.Reports {
		hr.Reports = append(hr.Reports, HealthCheck{
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

	w.Write([]byte("500 Internal Server Error"))
}
