package user

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/user Component

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/google/flatbuffers/go"
	"github.com/pkg/errors"
)

type key int

const (
	// CorrelationIDKey is the key for the correlation ID in the context.
	CorrelationIDKey key = iota

	// GRPCCorrelationIDKey is the key for the correlation ID in the GRPC metadata.
	GRPCCorrelationIDKey = "correlation_id"
	// LoggingCorrelationIDKey is the key for the correlation ID in the trace.
	LoggingCorrelationIDKey = "correlation_id"
	// InstrumentingCorrelationIDKey is the key for the correlation ID in the metric DB.
	InstrumentingCorrelationIDKey = "correlation_id"
	// TracingCorrelationIDKey is the key for the correlation ID in the trace.
	TracingCorrelationIDKey = "correlation_id"
	// TrackingCorrelationIDKey is the key for the correlation ID in sentry.
	TrackingCorrelationIDKey = "correlation_id"
)

// Component is the user component interface.
type Component interface {
	GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*fb.GetUsersResponse, error)
}

type component struct {
	module Module
}

// NewComponent returns a user component.
func NewComponent(module Module) Component {
	return &component{
		module: module,
	}
}

func (c *component) GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*fb.GetUsersResponse, error) {
	var users, err = c.module.GetUsers(ctx, string(req.Realm()))
	if err != nil {
		return nil, errors.Wrap(err, "module could not get users")
	}
	return fbUsersResponse(users), nil
}

func fbUsersResponse(users []string) *fb.GetUsersResponse {
	var b = flatbuffers.NewBuilder(0)

	var userOffsets = []flatbuffers.UOffsetT{}
	for _, u := range users {
		userOffsets = append(userOffsets, b.CreateString(u))
	}

	fb.GetUsersResponseStartNamesVector(b, len(users))
	for _, u := range userOffsets {
		b.PrependUOffsetT(u)
	}
	var names = b.EndVector(len(users))
	fb.GetUsersResponseStart(b)
	fb.GetUsersResponseAddNames(b, names)
	b.Finish(fb.GetUsersResponseEnd(b))

	return fb.GetRootAsGetUsersResponse(b.FinishedBytes(), 0)
}
