package user

//go:generate mockgen -destination=./mock/grpc.go -package=mock -mock_names=Handler=Handler github.com/go-kit/kit/transport/grpc Handler

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/go-kit/kit/endpoint"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	"github.com/google/flatbuffers/go"
	"github.com/pkg/errors"
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
	var val = md[GRPCCorrelationIDKey]

	// If there is no id in the metadata, return current context.
	if val == nil || val[0] == "" {
		return ctx
	}

	// If there is an id in the metadata, add it to the context.
	return context.WithValue(ctx, CorrelationIDKey, val[0])
}

// decodeGRPCRequest decodes the flatbuffer request.
func decodeGRPCRequest(_ context.Context, req interface{}) (interface{}, error) {
	return req, nil
}

// encodeHTTPReply encodes the flatbuffer reply.
func encodeGRPCReply(_ context.Context, rep interface{}) (interface{}, error) {
	return rep, nil
}

// Implement the flatbuffer UserServiceServer interface.
func (s *grpcServer) GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*flatbuffers.Builder, error) {
	var _, rep, err = s.getUsers.ServeGRPC(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "grpc server could not return next ID")
	}

	var reply = rep.(*fb.GetUsersResponse)

	var usersNames []string
	for i := 0; i < reply.NamesLength(); i++ {
		usersNames = append(usersNames, string(reply.Names(i)))
	}

	var b = flatbuffers.NewBuilder(0)
	var userOffsets = []flatbuffers.UOffsetT{}
	for _, u := range usersNames {
		userOffsets = append(userOffsets, b.CreateString(u))
	}

	fb.GetUsersResponseStartNamesVector(b, len(usersNames))
	for _, u := range userOffsets {
		b.PrependUOffsetT(u)
	}
	var names = b.EndVector(len(usersNames))
	fb.GetUsersResponseStart(b)
	fb.GetUsersResponseAddNames(b, names)
	b.Finish(fb.GetUsersResponseEnd(b))

	return b, nil
}
