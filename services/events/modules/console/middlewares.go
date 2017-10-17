package console

import (
	"time"
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
func (s *serviceLoggingMiddleware)Print(args ...string) {
	defer func(begin time.Time) {
		s.log.Log("method", "Print", "args", args, "took", time.Since(begin))
	}(time.Now())
	s.next.Print(args...)
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