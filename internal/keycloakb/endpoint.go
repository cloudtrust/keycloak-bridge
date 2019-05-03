package keycloakb

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/ratelimit"
	"golang.org/x/time/rate"
)

// ToGoKitEndpoint converts endpoints
func ToGoKitEndpoint(e cs.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return e(ctx, request)
	}
}

// LimitRate adds a rate limit to an endpoint
func LimitRate(e cs.Endpoint, limit int) endpoint.Endpoint {
	return ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), limit))(ToGoKitEndpoint(e))
}
