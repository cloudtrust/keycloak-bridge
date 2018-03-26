package health

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	InfluxHealthCheck   endpoint.Endpoint
	JaegerHealthCheck   endpoint.Endpoint
	RedisHealthCheck    endpoint.Endpoint
	SentryHealthCheck   endpoint.Endpoint
	KeycloakHealthCheck endpoint.Endpoint
	AllHealthChecks     endpoint.Endpoint
}

// MakeInfluxHealthCheckEndpoint makes the InfluxHealthCheck endpoint.
func MakeInfluxHealthCheckEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.InfluxHealthChecks(ctx), nil
	}
}

// MakeJaegerHealthCheckEndpoint makes the JaegerHealthCheck endpoint.
func MakeJaegerHealthCheckEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.JaegerHealthChecks(ctx), nil
	}
}

// MakeRedisHealthCheckEndpoint makes the RedisHealthCheck endpoint.
func MakeRedisHealthCheckEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.RedisHealthChecks(ctx), nil
	}
}

// MakeSentryHealthCheckEndpoint makes the SentryHealthCheck endpoint.
func MakeSentryHealthCheckEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.SentryHealthChecks(ctx), nil
	}
}

// MakeKeycloakHealthCheckEndpoint makes the KeycloakHealthCheck endpoint.
func MakeKeycloakHealthCheckEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.KeycloakHealthChecks(ctx), nil
	}
}

// MakeAllHealthChecksEndpoint makes an endpoint that does all health checks.
func MakeAllHealthChecksEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.AllHealthChecks(ctx), nil
	}
}
