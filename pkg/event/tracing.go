package event

import (
	"net/http"

	opentracing "github.com/opentracing/opentracing-go"
)

// Middleware on http transport.
type Middleware func(http.Handler) http.Handler

// MakeTracingMiddleware extracts the span from the http request.
func MakeTracingMiddleware(tracer opentracing.Tracer, operationName string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

			var sc, err = tracer.Extract(opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(req.Header))

			var span opentracing.Span
			if err != nil {
				span = tracer.StartSpan(operationName)
			} else {
				span = tracer.StartSpan(operationName, opentracing.ChildOf(sc))
			}
			defer span.Finish()

			next.ServeHTTP(w, req.WithContext(opentracing.ContextWithSpan(req.Context(), span)))
		})
	}
}
