package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/services/users/component"
	user_fb "github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer"
	"github.com/go-kit/kit/log"
	"github.com/google/flatbuffers/go"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

func NewGrpcService(conn *grpc.ClientConn) components.Service {
	return &grpcService{
		client: user_fb.NewUserServiceClient(conn),
	}
}

type grpcService struct {
	client user_fb.UserServiceClient
}

func (g *grpcService) GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	var builder = flatbuffers.NewBuilder(0)
	var brealm = builder.CreateString(realm)
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
			return resultc, errc
		}
	}
	go func() {
		for {
			var iUser *user_fb.UserReply
			var err error
			iUser, err = stream.Recv()
			if err != nil {
				errc <- err
				return
			}
			var user = string(iUser.Names(0))
			resultc <- user
		}
	}()
	return resultc, errc
}

func TestMain_Main(t *testing.T) {
	var grpcAddr = fmt.Sprintf("127.0.0.1:5555")

	var logger = log.NewLogfmtLogger(os.Stdout)
	{
		logger = log.With(logger, "time", log.DefaultTimestampUTC, "caller", "client")
		defer logger.Log("msg", "Goodbye")
	}

	var conn *grpc.ClientConn
	{
		var err error
		conn, err = grpc.Dial(grpcAddr, grpc.WithInsecure(), grpc.WithCodec(flatbuffers.FlatbuffersCodec{}))
		if err != nil {
			fmt.Println("I failed :(")
			return
		}
	}
	defer conn.Close()

	var userService = NewGrpcService(conn)
	var userResultc <-chan string
	var userErrc <-chan error
	userResultc, userErrc = userService.GetUsers(context.Background(), "master")

loop:
	for {
		select {
		case result := <-userResultc:
			t.Log(result)
		case err := <-userErrc:
			if err == io.EOF {
				break loop
			}
			t.Log(err)
			break loop
		}
	}
}
