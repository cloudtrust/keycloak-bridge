package middleware

import (
	"context"
	"net/http"

	gen "github.com/cloudtrust/keycloak-bridge/internal/idgenerator"
	"github.com/go-kit/kit/log"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	opentracing "github.com/opentracing/opentracing-go"
)

// MakeHTTPCorrelationIDMW retrieve the correlation ID from the HTTP header 'X-Correlation-ID'.
// It there is no such header, it generates a correlation ID.
func MakeHTTPCorrelationIDMW(idGenerator gen.IDGenerator, tracer opentracing.Tracer, logger log.Logger, componentName, componentID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var correlationID = req.Header.Get("X-Correlation-ID")

			if correlationID == "" {
				correlationID = idGenerator.NextID()
			}

			var ctx = context.WithValue(req.Context(), "correlation_id", correlationID)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

type correlationIDMW struct {
	idGenerator   gen.IDGenerator
	tracer        opentracing.Tracer
	logger        log.Logger
	componentName string
	componentID   string
	next          grpc_transport.Handler
}
