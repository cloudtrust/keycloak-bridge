package server

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/services/users/endpoint"
	"github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer/fb"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/google/flatbuffers/go"
)

/*
A grpcServer is essentially just a set of endpoints that can be called via GRPC.
*/
type grpcServer struct {
	getUsersHandler kitgrpc.Handler
}

/*
Returns a new UserServiceServer
*/
func NewGrpcServer(endpoints endpoints.Endpoints) fb.UserServiceServer {
	var getUsersHandler = kitgrpc.NewServer(
		endpoints.GetUsersEndpoint,
		decodeGrpcGetUsersRequest,
		encodeGrpcGetUsersResponse,
	)
	return &grpcServer{
		getUsersHandler: getUsersHandler,
	}
}

func decodeGrpcGetUsersRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	var req = grpcReq.(*fb.GetUsersRequest)
	return endpoints.GetUsersRequest{
		Realm: string(req.Realm()),
	}, nil
}

func encodeGrpcGetUsersResponse(_ context.Context, response interface{}) (interface{}, error) {
	var resp = response.(endpoints.GetUsersResponse)
	var b = flatbuffers.NewBuilder(0)
	var users = resp.Users
	var userOffs = []flatbuffers.UOffsetT{}
	{
		for _, u := range users {
			userOffs = append(userOffs, b.CreateString(u))
		}
	}
	fb.GetUsersResponseStartNamesVector(b, len(users))
	for _, u := range userOffs {
		b.PrependUOffsetT(u)
	}
	var names = b.EndVector(len(users))
	fb.GetUsersResponseStart(b)
	fb.GetUsersResponseAddNames(b, names)
	b.Finish(fb.GetUsersResponseEnd(b))
	return b, nil
}

/*
grpcServer implements fb.UserServiceServer
*/
func (u *grpcServer) GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*flatbuffers.Builder, error) {
	var _, resp, err = u.getUsersHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.(*flatbuffers.Builder), err
}
