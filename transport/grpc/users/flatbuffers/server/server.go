package server

import (
	"github.com/google/flatbuffers/go"
	"github.com/cloudtrust/keycloak-bridge/transport/grpc/users/flatbuffers/schema"
	"github.com/cloudtrust/keycloak-bridge/services/users"
	"io"
)

/*
A grpcServer is essentially just a set of endpoints that can be called via GRPC.
 */
type grpcServer struct {
	endpoints users.Endpoints
}

/*
Returns a new UserServiceServer
 */
func NewGrpcServer(endpoints users.Endpoints) schema.UserServiceServer {
	return &grpcServer{
		endpoints:endpoints,
	}
}

/*
grpcServer implements fb.UserServiceServer
 */
func (u *grpcServer)GetUsers(m *schema.UserRequest, s schema.UserService_GetUsersServer) error {
	var realm = string(m.Realm())
	var userc <- chan string
	var errc <- chan error
	userc, errc = u.endpoints.GetUsers(s.Context(), realm)
	for {
		select {
		case user := <-userc:
			var b = flatbuffers.NewBuilder(0)
			var name = b.CreateString(user)
			schema.UserReplyStartNamesVector(b,1)
			b.PrependUOffsetT(name)
			var names = b.EndVector(1)
			schema.UserReplyStart(b)
			schema.UserReplyAddNames(b, names)
			b.Finish(schema.UserReplyEnd(b))
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