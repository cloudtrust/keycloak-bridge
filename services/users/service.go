package users

import (
	keycloak "github.com/elca-kairos-py/keycloak-client/client"
	"context"
	"github.com/pkg/errors"
	"io"
	"github.com/google/flatbuffers/go"
	user_fb "github.com/cloudtrust/keycloak-bridge/transport/grpc/users/flatbuffers/schema"
	"google.golang.org/grpc"

)

/*
This is the interface that user services implement.
 */
type Service interface {
	GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error)
}

/*
 */
func NewBasicService(client keycloak.Client) Service {
	return &basicService{
		client:client,
	}
}

type basicService struct {
	client keycloak.Client
}

func (u *basicService)GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	var representations []keycloak.UserRepresentation
	{
		var err error
		representations, err = u.client.GetUsers(realm)
		if err != nil {
			go func(){
				errc <- errors.Wrap(err, "Couldn't get users!")
				return
			}()
			return resultc, errc
		}
	}
	go func(){
		for _,r := range representations {
			resultc <- *r.Username
		}
		errc <- io.EOF
	}()
	return resultc, errc
}

//Client Code. Shouldn't be here.

func NewGrpcService(conn *grpc.ClientConn) Service {
	return &grpcService{
		client:user_fb.NewUserServiceClient(conn),
	}
}

type grpcService struct {
	client user_fb.UserServiceClient
}

func (g *grpcService)GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	var builder= flatbuffers.NewBuilder(0)
	var brealm= builder.CreateString(realm)
	user_fb.UserRequestStart(builder)
	user_fb.UserRequestAddRealm(builder, brealm)
	builder.Finish(user_fb.UserReplyEnd(builder))
	var stream user_fb.UserService_GetUsersClient
	{
		var err error
		stream, err = g.client.GetUsers(context.Background(), builder)
		if err != nil {
			go func() {
				errc <- errors.Wrap(err, "Couldn't get users stream")
				return
			}()
			return resultc,errc
		}
	}
	go func() {
		for {
			var i_user *user_fb.UserReply
			var err error
			i_user, err = stream.Recv()
			if err != nil {
				errc <- err
				return
			}
			var user = string(i_user.Names(0))
			resultc <- user
		}
	}()
	return resultc, errc
}