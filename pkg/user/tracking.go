package user

import (
	"context"
	"strconv"

	"github.com/cloudtrust/keycloak-bridge/api/user/fb"
	sentry "github.com/getsentry/raven-go"
	"github.com/go-kit/kit/log"
)

// Sentry interface.
type Sentry interface {
	CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
}

// Tracking middleware at component level.
type trackingComponentMW struct {
	sentry Sentry
	logger log.Logger
	next   Component
}

// MakeComponentTrackingMW makes an error tracking middleware, where the errors are sent to Sentry.
func MakeComponentTrackingMW(sentry Sentry, logger log.Logger) func(Component) Component {
	return func(next Component) Component {
		return &trackingComponentMW{
			sentry: sentry,
			logger: logger,
			next:   next,
		}
	}
}

// trackingComponentMW implements Component.
func (m *trackingComponentMW) GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*fb.GetUsersReply, error) {
	var users, err = m.next.GetUsers(ctx, req)
	if err != nil {
		var corrID = ctx.Value("correlation_id").(string)
		var pack = strconv.FormatUint(uint64(req.Pack()), 10)
		var realm = string(req.Realm())

		var tags = map[string]string{
			"correlation_id": corrID,
			"realm":          realm,
			"pack":           pack,
		}

		m.sentry.CaptureError(err, tags)
		m.logger.Log("unit", "GetUsers", "correlation_id", corrID, "realm", realm, "pack", pack, "error", err.Error())
	}
	return users, err
}
