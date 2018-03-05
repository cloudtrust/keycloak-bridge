package event

//go:generate mockgen -destination=./mock/tracking.go -package=mock -mock_names=Sentry=Sentry github.com/cloudtrust/keycloak-bridge/pkg/event Sentry

import (
	"context"

	sentry "github.com/getsentry/raven-go"
)

const (
	// TrackingCorrelationIDKey is the key for the correlation ID in sentry.
	TrackingCorrelationIDKey = "correlation_id"
)

// Sentry interface.
type Sentry interface {
	CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
}

// Tracking middleware at component level.
type trackingComponentMW struct {
	sentry Sentry
	next   MuxComponent
}

// MakeComponentTrackingMW makes an error tracking middleware, where the errors are sent to Sentry.
func MakeComponentTrackingMW(sentry Sentry) func(MuxComponent) MuxComponent {
	return func(next MuxComponent) MuxComponent {
		return &trackingComponentMW{
			sentry: sentry,
			next:   next,
		}
	}
}

// trackingComponentMW implements MuxComponent.
func (m *trackingComponentMW) Event(ctx context.Context, eventType string, obj []byte) error {
	var err = m.next.Event(ctx, eventType, obj)
	if err != nil {
		m.sentry.CaptureError(err, map[string]string{TrackingCorrelationIDKey: ctx.Value(CorrelationIDKey).(string)})
	}
	return err
}
