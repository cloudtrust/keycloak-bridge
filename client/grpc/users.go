package main

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/go-kit/kit/log"
	"github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
	otag "github.com/opentracing/opentracing-go/ext"
	jaeger_client "github.com/uber/jaeger-client-go/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	address = "10.244.18.2:5550"
)

func main() {

	// Logger.
	var logger = log.NewLogfmtLogger(os.Stdout)
	{
		logger = log.With(logger, "time", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
		defer logger.Log("msg", "Goodbye")
	}
	logger = log.With(logger, "transport", "grpc")

	// Jaeger tracer config.
	var jaegerConfig = jaeger_client.Configuration{
		Sampler: &jaeger_client.SamplerConfig{
			Type:              "const",
			Param:             1,
			SamplingServerURL: "http://127.0.0.1:5775",
		},
		Reporter: &jaeger_client.ReporterConfig{
			LogSpans:            false,
			BufferFlushInterval: 1000 * time.Millisecond,
		},
	}

	// Jaeger client.
	var tracer opentracing.Tracer
	{
		var logger = log.With(logger, "component", "jaeger")
		var closer io.Closer
		var err error

		tracer, closer, err = jaegerConfig.New("keycloak-user-client")
		if err != nil {
			logger.Log("error", err)
			return
		}
		defer closer.Close()
	}

	// Set up a connection to the server.
	var clienConn *grpc.ClientConn
	{
		var err error
		clienConn, err = grpc.Dial(address, grpc.WithInsecure(), grpc.WithCodec(flatbuffers.FlatbuffersCodec{}))
		if err != nil {
			logger.Log("error", err)
		}
		defer clienConn.Close()
	}

	// Client.
	var client = fb.NewUserServiceClient(clienConn)

	var span = tracer.StartSpan("grpc_client_getusers")
	otag.SpanKindRPCClient.Set(span)
	defer span.Finish()

	// Propagate the opentracing span.
	var carrier = make(opentracing.TextMapCarrier)
	var err = tracer.Inject(span.Context(), opentracing.TextMap, carrier)
	if err != nil {
		logger.Log("error", err)
		return
	}

	var md = metadata.New(carrier)
	var correlationIDMD = metadata.New(map[string]string{})

	var b = flatbuffers.NewBuilder(0)
	var brealm = b.CreateString("master")
	fb.GetUsersRequestStart(b)
	fb.GetUsersRequestAddRealm(b, brealm)
	b.Finish(fb.GetUsersRequestEnd(b))

	var reply *fb.GetUsersResponse
	{
		var err error
		var ctx = metadata.NewOutgoingContext(opentracing.ContextWithSpan(context.Background(), span), metadata.Join(md, correlationIDMD))
		reply, err = client.GetUsers(ctx, b)
		if err != nil {
			logger.Log("error", err)
			return
		}
		for i := 0; i < reply.NamesLength(); i++ {
			logger.Log("name", string(reply.Names(i)))
		}
	}
}
