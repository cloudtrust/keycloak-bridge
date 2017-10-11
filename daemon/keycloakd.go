package main

import (
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

	events_components "github.com/cloudtrust/keycloak-bridge/services/events/components"
	events_console "github.com/cloudtrust/keycloak-bridge/services/events/modules/console"
	events_endpoints "github.com/cloudtrust/keycloak-bridge/services/events/endpoints"
	events_transport "github.com/cloudtrust/keycloak-bridge/services/events/transport"

	users_transport "github.com/cloudtrust/keycloak-bridge/services/users/transport"
	users_flatbuf "github.com/cloudtrust/keycloak-bridge/services/users/transport/flatbuffer"
	users_components "github.com/cloudtrust/keycloak-bridge/services/users/components"
	users_endpoints "github.com/cloudtrust/keycloak-bridge/services/users/endpoints"
	users_keycloak "github.com/cloudtrust/keycloak-bridge/services/users/modules/keycloak"
)

var VERSION string = "123"

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


	/********
	User stack
	 *********/

	var keycloakModule users_keycloak.Service
	{
		keycloakModule = users_keycloak.NewBasicService(keycloakClient)
	}


	var userComponent users_components.Service
	{
		var logger = log.With(logger)
		userComponent = users_components.NewBasicService(keycloakModule)
		userComponent = users_components.MakeServiceLoggingMiddleware(logger)(userComponent)
	}


	/*
	Endpoint configurations
	 */
	var getUsersEndpoint endpoint.Endpoint
	{
		var logger = log.With(logger, "Method", "GetUsers")
		var innerLogger = log.With(logger, "InnerMethod", "GetUser")
		getUsersEndpoint = users_endpoints.MakeGetUsersEndpoint(
			userComponent,
			users_endpoints.MakeEndpointLoggingMiddleware(innerLogger, "outer_req_id", "inner_req_id", ),
			users_endpoints.MakeEndpointSnowflakeMiddleware("inner_req_id"),
		)
		getUsersEndpoint = users_endpoints.MakeEndpointLoggingMiddleware(logger, "outer_req_id")(getUsersEndpoint)
		getUsersEndpoint = users_endpoints.MakeEndpointSnowflakeMiddleware("outer_req_id")(getUsersEndpoint)
	}

	var users_endpoints = users_endpoints.Endpoints{
		GetUsersEndpoint:getUsersEndpoint,
	}

	/*
	GRPC server instantiation :
		The above Endpoints is used as a GRPC endpoint directly, shortcutting go-kit's facilities.
	 */
	go func() {
		var userServer = users_transport.NewGrpcServer(users_endpoints)
		var userGrpcServer = grpc.NewServer(grpc.CustomCodec(flatbuffers.FlatbuffersCodec{}))
		users_flatbuf.RegisterUserServiceServer(userGrpcServer, userServer)
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
	Event stack
	 */
	var consoleModule events_console.Service
	{
		consoleModule = events_console.NewBasicService()
		consoleModule = events_console.MakeServiceLoggingMiddleware(logger)(consoleModule)
	}


	var eventComponent events_components.Service
	{
		eventComponent = events_components.NewBasicService(consoleModule)
		eventComponent = events_components.MakeServiceLoggingMiddleware(logger)(eventComponent)
	}

	var eventConsumerEndpoint endpoint.Endpoint
	{
		eventConsumerEndpoint = events_endpoints.MakeKeycloakEventsReceiverEndpoint(eventComponent)
		eventConsumerEndpoint = events_endpoints.MakeEndpointLoggingMiddleware(logger)(eventConsumerEndpoint)
	}

	var events_endpoints = events_endpoints.Endpoints{
		KeycloakEventsReceiverEndpoint:eventConsumerEndpoint,
	}


	/*
	HTTP monitoring routes.
	  */
	go func() {
		logger := log.With(logger, "transport", "HTTP")

		route := mux.NewRouter()

		route.Handle("/version", http.HandlerFunc(MakeVersion(VERSION)))

		//debug
		debugSubroute := route.PathPrefix("/debug").Subrouter()
		debugSubroute.HandleFunc("/pprof/", http.HandlerFunc(pprof.Index))
		debugSubroute.HandleFunc("/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		debugSubroute.HandleFunc("/pprof/profile", http.HandlerFunc(pprof.Profile))
		debugSubroute.HandleFunc("/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		debugSubroute.HandleFunc("/pprof/trace", http.HandlerFunc(pprof.Trace))

		//event
		eventSubroute := route.PathPrefix("/event").Subrouter()
		eventSubroute.Handle("/{id}", events_transport.MakeReceiverHandler(events_endpoints.KeycloakEventsReceiverEndpoint, logger))

		//other

		logger.Log("addr", httpAddr)

		errc <- http.ListenAndServe(httpAddr, route)
	}()



	logger.Log("error", <-errc)
}

func MakeVersion(version string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("Application version : %s\n", version)))
	}
}
