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
func (s *serviceLoggingMiddleware)ConsumeEvents(ctx context.Context, event string) {
	defer func(begin time.Time) {
		s.log.Log("method", "ConsumeEvents", "event", event, "took", time.Since(begin))
	}(time.Now())
	s.next.ConsumeEvents(ctx, event)
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