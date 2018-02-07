package event

import (
	"context"

	sentry "github.com/getsentry/raven-go"
)

// Sentry interface.
type Sentry interface {
	CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
}

// Tracking middleware at component level.
type trackingComponentMW struct {
	client Sentry
	next   MuxComponent
}

// MakeComponentTrackingMW makes an error tracking middleware, where the errors are sent to Sentry.
func MakeComponentTrackingMW(client Sentry) func(MuxComponent) MuxComponent {
	return func(next MuxComponent) MuxComponent {
		return &trackingComponentMW{
			client: client,
			next:   next,
		}
	}
}

// trackingComponentMW implements MuxComponent.
func (m *trackingComponentMW) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	var r, err = m.next.Event(ctx, eventType, obj)
	if err != nil {
		m.client.CaptureError(err, map[string]string{"correlation_id": ctx.Value("correlation_id").(string)})
	}
	return r, err
}
