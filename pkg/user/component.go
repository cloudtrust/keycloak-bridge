package user

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/user Component

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/google/flatbuffers/go"
	"github.com/pkg/errors"
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
