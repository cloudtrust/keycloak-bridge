package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/services/users/components"
	user_fb "github.com/cloudtrust/keycloak-bridge/services/users/transport/fb"
	"github.com/go-kit/kit/log"
	"github.com/google/flatbuffers/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func NewGrpcService(conn *grpc.ClientConn) components.Service {
	return &grpcService{
		client: user_fb.NewUserServiceClient(conn),
	}
}

type grpcService struct {
	client user_fb.UserServiceClient
}

func (g *grpcService) GetUsers(ctx context.Context, realm string) ([]string, error) {
	var builder = flatbuffers.NewBuilder(0)
	var brealm = builder.CreateString(realm)
	user_fb.GetUsersRequestStart(builder)
	user_fb.GetUsersRequestAddRealm(builder, brealm)
	builder.Finish(user_fb.GetUsersRequestEnd(builder))
	var resp *user_fb.GetUsersResponse
	{
		var ctx = metadata.NewOutgoingContext(context.Background(), metadata.New(map[string]string{"id": strconv.FormatUint(1423, 10)}))
		var err error
		resp, err = g.client.GetUsers(context.Background(), builder)
		if err != nil {
			return nil, err
		}
	}
	var users []string
	{
		for i := 0; i < resp.NamesLength(); i++ {
			users = append(users, string(resp.Names(i)))
		}
	}
	return users, nil
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

	var users, err = userService.GetUsers(context.Background(), "master")
	t.Log("result", users, "error", err)
}
