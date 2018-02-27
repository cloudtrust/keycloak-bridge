package user

//go:generate mockgen -destination=./mock/grpc.go -package=mock -mock_names=Handler=Handler github.com/go-kit/kit/transport/grpc Handler

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/go-kit/kit/endpoint"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	"github.com/google/flatbuffers/go"
	"google.golang.org/grpc/metadata"
)

type grpcServer struct {
	getUsers grpc_transport.Handler
}

// MakeGRPCGetUsersHandler makes a GRPC handler for the GetUsers endpoint.
func MakeGRPCGetUsersHandler(e endpoint.Endpoint) *grpc_transport.Server {
	return grpc_transport.NewServer(
		e,
		decodeGRPCRequest,
		encodeGRPCReply,
		grpc_transport.ServerBefore(fetchGRPCCorrelationID),
	)
}

// NewGRPCServer makes a set of handler available as a UserServiceServer.
func NewGRPCServer(getUsers grpc_transport.Handler) fb.UserServiceServer {
	return &grpcServer{getUsers: getUsers}
}

// fetchGRPCCorrelationID reads the correlation ID from the GRPC metadata.
// If the id is not zero, we put it in the context.
func fetchGRPCCorrelationID(ctx context.Context, md metadata.MD) context.Context {
	var val = md["correlation_id"]

	// If there is no id in the metadata, return current context.
	if val == nil || val[0] == "" {
		return ctx
	}

	// If there is an id in the metadata, add it to the context.
	var id = val[0]
	return context.WithValue(ctx, "correlation_id", id)
}

// decodeGRPCRequest decodes the flatbuffer request.
func decodeGRPCRequest(_ context.Context, req interface{}) (interface{}, error) {
	var r = req.(*fb.GetUsersRequest)
	return GetUsersRequest{Realm: string(r.Realm())}, nil
}

// encodeHTTPReply encodes the flatbuffer reply.
func encodeGRPCReply(_ context.Context, res interface{}) (interface{}, error) {
	var r = res.(GetUsersResponse)
	var b = flatbuffers.NewBuilder(0)

	var userOffs = []flatbuffers.UOffsetT{}
	for _, u := range r.Users {
		userOffs = append(userOffs, b.CreateString(u))
	}

	fb.GetUsersResponseStartNamesVector(b, len(r.Users))
	for _, u := range userOffs {
		b.PrependUOffsetT(u)
	}
	var names = b.EndVector(len(r.Users))
	fb.GetUsersResponseStart(b)
	fb.GetUsersResponseAddNames(b, names)
	b.Finish(fb.GetUsersResponseEnd(b))
	return b, nil
}

// Implement the flatbuffer UserServiceServer interface.
func (u *grpcServer) GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*flatbuffers.Builder, error) {
	var _, resp, err = u.getUsers.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.(*flatbuffers.Builder), err
}
