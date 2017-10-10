package server

import (
	"github.com/google/flatbuffers/go"
	"github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer"
	"io"
	"github.com/cloudtrust/keycloak-bridge/services/users/endpoints"
)

/*
A grpcServer is essentially just a set of endpoints that can be called via GRPC.
 */
type grpcServer struct {
	endpoints endpoints.Endpoints
}

/*
Returns a new UserServiceServer
 */
func NewGrpcServer(endpoints endpoints.Endpoints) flatbuffer.UserServiceServer {
	return &grpcServer{
		endpoints:endpoints,
	}
}

/*
grpcServer implements fb.UserServiceServer
 */
func (u *grpcServer)GetUsers(m *flatbuffer.UserRequest, s flatbuffer.UserService_GetUsersServer) error {
	var realm = string(m.Realm())
	var userc <- chan string
	var errc <- chan error
	userc, errc = u.endpoints.GetUsers(s.Context(), realm)
	for {
		select {
		case user := <-userc:
			var b = flatbuffers.NewBuilder(0)
			var name = b.CreateString(user)
			flatbuffer.UserReplyStartNamesVector(b,1)
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
}