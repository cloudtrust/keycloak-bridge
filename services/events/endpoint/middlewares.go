package endpoints

import (
	"context"
	"strconv"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"

	events "github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/fb"
	transport "github.com/cloudtrust/keycloak-bridge/services/events/transport/http"
	stdopentracing "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
	otlog "github.com/opentracing/opentracing-go/log"
)

// MakeCorrelationIDMiddleware makes a middleware that takes the id from Keycloak and
// includes it in the context
func MakeCorrelationIDMiddleware() endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var id int64
			switch eventRequest := req.(type) {
			case transport.EventRequest:
				switch eventRequest.Type {
				case "AdminEvent":
					var adminEvent *events.AdminEvent
					adminEvent = events.GetRootAsAdminEvent(eventRequest.Object, 0)
					id = adminEvent.Uid()
				case "Event":
					var event *events.Event
					event = events.GetRootAsEvent(eventRequest.Object, 0)
					id = event.Uid()
				default:
					return nil, errors.New("Wrong type of event")
				}
			default:
				return nil, errors.New("Wrong type of request")
			}
			var newCtx = context.WithValue(ctx, "id", strconv.FormatInt(id, 10))
			return next(newCtx, req)

		}

	}
}

/*
MakeEndpointLoggingMiddleware returns the Logging Middleware for Endpoints.
*/
func MakeEndpointLoggingMiddleware(logger log.Logger, keys ...interface{}) endpoint.Middleware {

	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (resp interface{}, err error) {
			var vaList []interface{}
			vaList = append(vaList, "Method", "Endpoint")
			vaList = append(vaList, "id", ctx.Value("id").(string))
			vaList = append(vaList, "err", err)
			for _, key := range keys {
				vaList = append(vaList, key, ctx.Value(key))
			}
			defer func(begin time.Time) {
				vaList = append(vaList, "took", time.Since(begin))
				logger.Log(vaList...)
			}(time.Now())
			return next(ctx, req)
		}
	}
}

//MakeEndpointTracingMiddleware wraps Endpoint with a tracer
func MakeEndpointTracingMiddleware(tracer stdopentracing.Tracer, operationName string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			var span = stdopentracing.SpanFromContext(ctx)
			if span == nil {
				//create a new root span.
				span = tracer.StartSpan(operationName)
				span.SetTag("id", ctx.Value("id").(string))
				span.LogFields(otlog.String("operation", operationName),
					otlog.String("microservice_level", "endpoint"))

				otext.SpanKindRPCServer.Set(span)
				ctx = stdopentracing.ContextWithSpan(ctx, span)
				defer span.Finish()
				return next(ctx, request)
			}
			cspan := stdopentracing.StartSpan(operationName, stdopentracing.ChildOf(span.Context()))
			span.SetTag("id", ctx.Value("id").(string))
			defer cspan.Finish()
			//defer span.Finish()
			cspan.LogFields(otlog.String("operation", operationName),
				otlog.String("microservice_level", "endpoint"))

			otext.SpanKindRPCServer.Set(cspan)
			ctx = stdopentracing.ContextWithSpan(ctx, cspan)
			return next(ctx, request)
		}
	}
}
