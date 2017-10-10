package main

import (
	user_server "github.com/cloudtrust/keycloak-bridge/transport/grpc/users/flatbuffers/server"
	user_fb "github.com/cloudtrust/keycloak-bridge/transport/grpc/users/flatbuffers/schema"
	"github.com/google/flatbuffers/go"
	keycloak_client "github.com/cloudtrust/keycloak-client/client"
	user_service "github.com/cloudtrust/keycloak-bridge/services/users"
	http_monitoring "github.com/cloudtrust/keycloak-bridge/transport/http/monitoring"
	bucket "github.com/juju/ratelimit"
	"github.com/asaskevich/EventBus"
	"github.com/gorilla/mux"
	"github.com/go-kit/kit/ratelimit"
	"github.com/go-kit/kit/log"
	"net"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"google.golang.org/grpc"
	"time"
	"github.com/go-kit/kit/endpoint"
	"context"
	"io"
	"net/http"
	"net/http/pprof"
	"github.com/cloudtrust/keycloak-bridge/transport/http/event-receiver"
)

var VERSION string

func main() {

	/*
	Configurations
	 */
	var (
		grpcAddr= fmt.Sprintf("127.0.0.1:5555")
		httpConfig = keycloak_client.HttpConfig{
			Addr:     "http://172.17.0.2:8080",
			Username: "admin",
			Password: "admin",
			Timeout:  time.Second * 5,
		}
		httpAddr = fmt.Sprintf("0.0.0.0:8888")
	)


	/*
	Critical errors channel
	 */
	var errc= make(chan error)

	/*
	Logger
	 */
	var logger= log.NewLogfmtLogger(os.Stdout)
	{
		logger = log.With(logger, "time", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
		defer logger.Log("msg", "Goodbye")
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	/*
	Create the keycloak client
	 */
	var keycloakClient keycloak_client.Client
	{
		var logger = log.With(logger, "gRPC config", grpcAddr, "Keycloak Config", httpConfig)
		var err error
		keycloakClient, err = keycloak_client.NewHttpClient(httpConfig)
		if err != nil {
			logger.Log("Couldn't create keycloak client", err)
			return
		}
	}

	/*
	Backend Service
	 */
	var getUsersService user_service.Service
	{
		var logger = log.With(logger)
		getUsersService = user_service.NewBasicService(keycloakClient)
		getUsersService = user_service.MakeServiceLoggingMiddleware(logger)(getUsersService)
	}

	/*
	Endpoint configurations
	 */
	var getUsersEndpoint endpoint.Endpoint
	{
		var logger = log.With(logger, "Method", "GetUsers")
		var innerLogger = log.With(logger, "InnerMethod", "GetUser")
		getUsersEndpoint = user_service.MakeGetUsersEndpoint(
			getUsersService,
			user_service.MakeEndpointLoggingMiddleware(innerLogger, "outer_req_id", "inner_req_id", ),
			user_service.MakeEndpointSnowflakeMiddleware("inner_req_id"),
		)
		getUsersEndpoint = user_service.MakeEndpointLoggingMiddleware(logger, "outer_req_id")(getUsersEndpoint)
		getUsersEndpoint = user_service.MakeEndpointSnowflakeMiddleware("outer_req_id")(getUsersEndpoint)
	}

	var endpoints = user_service.Endpoints{
		GetUsersEndpoint:getUsersEndpoint,
	}

	/*
	GRPC server instantiation :
		The above Endpoints is used as a GRPC endpoint directly, shortcutting go-kit's facilities.
	 */
	go func() {
		var userServer = user_server.NewGrpcServer(endpoints)
		var userGrpcServer = grpc.NewServer(grpc.CustomCodec(flatbuffers.FlatbuffersCodec{}))
		user_fb.RegisterUserServiceServer(userGrpcServer, userServer)
		var lis net.Listener
		{
			var err error
			lis, err = net.Listen("tcp", grpcAddr)
			if err != nil {
				logger.Log("Couldn't initialize listener", err)
				errc <- err
				return
			}
		}
		errc <- userGrpcServer.Serve(lis)
	}()

	/*
	HTTP monitoring routes.
	  */
	go func() {
		logger := log.With(logger, "transport", "HTTP")

		route := mux.NewRouter()

		route.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
		route.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		route.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		route.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		route.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))

		route.Handle("/event-receiver", http.HandlerFunc(event_receiver.MakeReceiver()))

		route.Handle("/version", http.HandlerFunc(http_monitoring.MakeVersion(VERSION)))
		logger.Log("addr", httpAddr)
		errc <- http.ListenAndServe(httpAddr, route)
	}()


	/*
	Run the client multiple times.
	test is a bad name.
	 */
	for i:=0; i<4; i++ {
		test()
	}

	logger.Log("error", <-errc)
}

func test() {
	var grpcAddr= fmt.Sprintf("127.0.0.1:5555")

	var logger= log.NewLogfmtLogger(os.Stdout)
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

	var userService = user_service.NewGrpcService(conn)
	var getUsersEndpoint endpoint.Endpoint
	{
		var logger = log.With(logger, "Method", "getUsers")
		var innerLogger  = log.With(logger, "InnerMethod", "getUser")
		var rateLimiter = bucket.NewBucket(1 * time.Millisecond, 2)
		getUsersEndpoint = user_service.MakeGetUsersEndpoint(
			userService,
			ratelimit.NewTokenBucketThrottler(rateLimiter, nil),
			user_service.MakeEndpointLoggingMiddleware(innerLogger, ),
		)
		getUsersEndpoint = user_service.MakeEndpointLoggingMiddleware(logger, )(getUsersEndpoint)
	}

	var endpointService = user_service.Endpoints{
		GetUsersEndpoint:getUsersEndpoint,
	}

	var userResultc <-chan string;
	var userErrc <-chan error;
	userResultc, userErrc = endpointService.GetUsers(context.Background(), "master")
	loop:for {
		select{
		case result := <-userResultc:
			fmt.Println(result)
		case err := <-userErrc:
			if err == io.EOF {
				break loop
			}
			fmt.Println(err)
			break loop
		}
	}
}