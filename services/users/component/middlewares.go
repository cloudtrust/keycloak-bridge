package components

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"google.golang.org/grpc/metadata"
)

/*
Service Middleware declarations
*/
type Middleware func(Service) Service

/*
Logging Middleware
*/
type serviceLoggingMiddleware struct {
	log  log.Logger
	next Service
}

/*
serviceLoggingMiddleware implements Service
*/
func (s *serviceLoggingMiddleware) GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var md, _ = metadata.FromIncomingContext(ctx)
	defer func(begin time.Time) {
		s.log.Log("method", "GetUsers", "id", md["id"][0], "realm", realm, "took", time.Since(begin))
	}(time.Now())
	return s.next.GetUsers(ctx, realm)
}

/*
Logging middleware for backend services.
*/
func MakeServiceLoggingMiddleware(log log.Logger) Middleware {
	return func(next Service) Service {
		return &serviceLoggingMiddleware{
			log:  log,
			next: next,
		}
	}
}
