package main

import (
	user_server "github.com/cloudtrust/keycloak-bridge/services/users/transport"
	user_fb "github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer"
	"github.com/google/flatbuffers/go"
	keycloak_client "github.com/cloudtrust/keycloak-client/client"
	"github.com/gorilla/mux"
	"github.com/go-kit/kit/log"
	"net"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"google.golang.org/grpc"
	"time"
	"github.com/go-kit/kit/endpoint"
	"net/http"
	"net/http/pprof"
	//"github.com/cloudtrust/keycloak-bridge/transport/http/event-receiver"
	keycloak "github.com/cloudtrust/keycloak-bridge/services/users/modules/keycloak"
	"github.com/cloudtrust/keycloak-bridge/services/users/components"
	"github.com/cloudtrust/keycloak-bridge/services/users/endpoints"
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
	var keycloakModule keycloak.Service
	{
		keycloakModule = keycloak.NewBasicService(keycloakClient)
	}


	var userComponent components.Service
	{
		var logger = log.With(logger)
		userComponent = components.NewBasicService(keycloakModule)
		userComponent = components.MakeServiceLoggingMiddleware(logger)(userComponent)
	}


	/*
	Endpoint configurations
	 */
	var getUsersEndpoint endpoint.Endpoint
	{
		var logger = log.With(logger, "Method", "GetUsers")
		var innerLogger = log.With(logger, "InnerMethod", "GetUser")
		getUsersEndpoint = endpoints.MakeGetUsersEndpoint(
			userComponent,
			endpoints.MakeEndpointLoggingMiddleware(innerLogger, "outer_req_id", "inner_req_id", ),
			endpoints.MakeEndpointSnowflakeMiddleware("inner_req_id"),
		)
		getUsersEndpoint = endpoints.MakeEndpointLoggingMiddleware(logger, "outer_req_id")(getUsersEndpoint)
		getUsersEndpoint = endpoints.MakeEndpointSnowflakeMiddleware("outer_req_id")(getUsersEndpoint)
	}

	var endpoints = endpoints.Endpoints{
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

		//debug
		debugSubroute := route.PathPrefix("debug").Subrouter()
		debugSubroute.HandleFunc("/debug/pprof/", http.HandlerFunc(pprof.Index))
		debugSubroute.HandleFunc("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		debugSubroute.HandleFunc("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		debugSubroute.HandleFunc("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		debugSubroute.HandleFunc("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))

		//event
		//eventSubroute := route.PathPrefix("event").Subrouter()
		//eventSubroute.Handle("/", http.HandlerFunc(event_receiver.MakeReceiver()))
		//eventSubroute.Handle("/", http.HandlerFunc(event_receiver.MakeReceiver()))

		//other

		logger.Log("addr", httpAddr)

		errc <- http.ListenAndServe(httpAddr, route)
	}()

	logger.Log("error", <-errc)
}
