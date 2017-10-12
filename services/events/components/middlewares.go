package components

import (
	"time"
	"context"
	"github.com/go-kit/kit/log"
)

/*
Service Middleware declarations
 */
type Middleware func(Service) Service


/*
Logging Middleware
 */
type serviceLoggingMiddleware struct {
	log log.Logger
	next Service
}

/*
serviceLoggingMiddleware implements Service
 */
func (s *serviceLoggingMiddleware)Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Event", eventType, "took", time.Since(begin))
	}(time.Now())
	s.next.Event(ctx, eventType, obj)
}

/*
Logging middleware for backend services.
 */
func MakeServiceLoggingMiddleware(log log.Logger) Middleware {
	return func(next Service) Service{
		return &serviceLoggingMiddleware {
			log: log,
			next: next,
		}
	}
}