package keycloakb

import (
	errors "github.com/pkg/errors"
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"

	fb "github.com/cloudtrust/keycloak-bridge/api/flaki/fb"
	flatbuffers "github.com/google/flatbuffers/go"
)

// NoopCockroach is a cockroach client that does nothing.
type NoopFlakiClient struct{}

func (c NoopFlakiClient) NextID(ctx context.Context, in *flatbuffers.Builder,
	opts ...grpc.CallOption) (*fb.FlakiReply, error) {
	return nil, errors.New("Flaki is disabled")
}

func (c NoopFlakiClient) NextValidID(ctx context.Context, in *flatbuffers.Builder,
	opts ...grpc.CallOption) (*fb.FlakiReply, error) {
	return nil, errors.New("Flaki is disabled")
}
