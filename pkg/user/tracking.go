package user

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
	sentry Sentry
	next   Component
}

// MakeComponentTrackingMW makes an error tracking middleware, where the errors are sent to Sentry.
func MakeComponentTrackingMW(sentry Sentry) func(Component) Component {
	return func(next Component) Component {
		return &trackingComponentMW{
			sentry: sentry,
			next:   next,
		}
	}
}

// trackingComponentMW implements Component.
func (m *trackingComponentMW) GetUsers(ctx context.Context, realm string) ([]string, error) {
	var users, err = m.next.GetUsers(ctx, realm)
	if err != nil {
		m.sentry.CaptureError(err, map[string]string{"correlation_id": ctx.Value("correlation_id").(string)})
	}
	return users, err
}
