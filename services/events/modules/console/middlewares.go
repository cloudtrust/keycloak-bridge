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
func (s *serviceLoggingMiddleware)Print(m map[string]string) error {
	defer func(begin time.Time) {
		s.log.Log("method", "Console.Print", "args", m, "took", time.Since(begin))
	}(time.Now())
	return s.next.Print(m)
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