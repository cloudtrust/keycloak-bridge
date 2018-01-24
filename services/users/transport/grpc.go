package server

import (
<<<<<<< HEAD
	"io"

	"github.com/cloudtrust/keycloak-bridge/services/users/endpoint"
	flatbuffer "github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer/fb"
=======
	"context"

	"github.com/cloudtrust/keycloak-bridge/services/users/endpoints"
	"github.com/cloudtrust/keycloak-bridge/services/users/transport/fb"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
>>>>>>> origin/refactor_user
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
<<<<<<< HEAD
func NewGrpcServer(endpoints endpoints.Endpoints) flatbuffer.UserServiceServer {
	return &grpcServer{
		endpoints: endpoints,
=======
func NewGrpcServer(endpoints endpoints.Endpoints) fb.UserServiceServer {
	var getUsersHandler = kitgrpc.NewServer(
		endpoints.GetUsersEndpoint,
		decodeGrpcGetUsersRequest,
		encodeGrpcGetUsersResponse,
	)
	return &grpcServer{
		getUsersHandler: getUsersHandler,
>>>>>>> origin/refactor_user
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
	fb.GetUsersResponseStart(b)
	fb.GetUsersResponseStartNamesVector(b, len(users))
	for _, u := range users {
		b.PrependUOffsetT(b.CreateString(u))
	}
	b.EndVector(len(users))
	b.Finish(fb.GetUsersResponseEnd(b))
	return b, nil
}

/*
grpcServer implements fb.UserServiceServer
*/
<<<<<<< HEAD
func (u *grpcServer) GetUsers(m *flatbuffer.UserRequest, s flatbuffer.UserService_GetUsersServer) error {
	var realm = string(m.Realm())
	var userc <-chan string
	var errc <-chan error
	userc, errc = u.endpoints.GetUsers(s.Context(), realm)
	for {
		select {
		case user := <-userc:
			var b = flatbuffers.NewBuilder(0)
			var name = b.CreateString(user)
			flatbuffer.UserReplyStartNamesVector(b, 1)
			b.PrependUOffsetT(name)
			var names = b.EndVector(1)
			flatbuffer.UserReplyStart(b)
			flatbuffer.UserReplyAddNames(b, names)
			b.Finish(flatbuffer.UserReplyEnd(b))
			if err := s.Send(b); err != nil {
				return err
			}
		case err := <-errc:
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
=======
func (u *grpcServer) GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*flatbuffers.Builder, error) {
	var _, resp, err = u.getUsersHandler.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.(*flatbuffers.Builder), err
>>>>>>> origin/refactor_user
}
