package event

//go:generate mockgen -destination=./mock/tracking.go -package=mock -mock_names=Sentry=Sentry github.com/cloudtrust/keycloak-bridge/pkg/event Sentry

import (
	"context"
	"encoding/base64"

	cs "github.com/cloudtrust/common-service"
	sentry "github.com/getsentry/raven-go"
	"github.com/go-kit/kit/log"
)

// Sentry interface.
type Sentry interface {
	CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
}

// Tracking middleware at component level.
type trackingMuxComponentMW struct {
	sentry Sentry
	logger log.Logger
	next   MuxComponent
}

// MakeMuxComponentTrackingMW makes an error tracking middleware, where the errors are sent to Sentry.
func MakeMuxComponentTrackingMW(sentry Sentry, logger log.Logger) func(MuxComponent) MuxComponent {
	return func(next MuxComponent) MuxComponent {
		return &trackingMuxComponentMW{
			sentry: sentry,
			logger: logger,
			next:   next,
		}
	}
}

// trackingComponentMW implements MuxComponent.
func (m *trackingMuxComponentMW) Event(ctx context.Context, eventType string, obj []byte) error {
	var err = m.next.Event(ctx, eventType, obj)
	if err != nil {
		var corrID = ctx.Value(cs.CtContextCorrelationID).(string)
		var b64Obj = base64.StdEncoding.EncodeToString(obj)

		var tags = map[string]string{
			"correlation_id": corrID,
			"event_type":     eventType,
			"obj":            b64Obj,
		}

		m.sentry.CaptureError(err, tags)
		m.logger.Log("unit", "Event", "correlation_id", corrID, "event_type", eventType, "obj", b64Obj, "error", err.Error())
	}
	return err
}
