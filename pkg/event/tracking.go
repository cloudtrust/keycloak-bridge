package event

import (
	"context"

	sentry "github.com/getsentry/raven-go"
	"github.com/go-kit/kit/log"
)

type Sentry interface {
	CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
}

/*
Error Middleware
*/
type serviceErrorMiddleware struct {
	log    log.Logger
	client Sentry
	next   MuxService
}

func (s *serviceErrorMiddleware) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	var i, err = s.next.Event(ctx, eventType, obj)
	if err != nil {
		s.log.Log("msg", "Send error to Sentry", "id", ctx.Value("id").(string), "error", err)
		s.client.CaptureError(err, nil)
	}
	return i, err
}

//MakeServiceErrorMiddleware wraps the MuxService with error tracking
func MakeServiceErrorMiddleware(log log.Logger, client Sentry) MuxMiddleware {
	return func(next MuxService) MuxService {
		return &serviceErrorMiddleware{
			log:    log,
			client: client,
			next:   next,
		}
	}
}
