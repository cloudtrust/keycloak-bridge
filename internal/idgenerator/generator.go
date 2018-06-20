package idgenerator

import (
	"context"
	"math/rand"
	"strconv"

	"github.com/cloudtrust/keycloak-bridge/api/flaki/fb"
	flaki "github.com/cloudtrust/keycloak-bridge/api/flaki/fb"
	flatbuffers "github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
	"google.golang.org/grpc/metadata"
)

// New returns an ID generator that query the distributed unique IDs generator.
func New(client flaki.FlakiClient, tracer opentracing.Tracer) *IDGenerator {
	return &IDGenerator{
		client: client,
		tracer: tracer,
	}
}

type IDGenerator struct {
	client flaki.FlakiClient
	tracer opentracing.Tracer
}

func (g *IDGenerator) NextID() string {
	var span = g.tracer.StartSpan("get_correlation_id")
	defer span.Finish()

	var ctx = g.contextWithTracer(span)

	// Flaki request.
	var b = flatbuffers.NewBuilder(0)
	fb.FlakiRequestStart(b)
	b.Finish(fb.FlakiRequestEnd(b))

	var reply *fb.FlakiReply
	{
		var err error
		reply, err = g.client.NextValidID(ctx, b)
		if err != nil {
			return g.degradedID()
		}
	}

	return string(reply.Id())
}

func (g *IDGenerator) contextWithTracer(span opentracing.Span) context.Context {
	var ctx = opentracing.ContextWithSpan(context.Background(), span)

	// Propagate the opentracing span.
	var carrier = make(opentracing.TextMapCarrier)
	var err = g.tracer.Inject(span.Context(), opentracing.TextMap, carrier)
	if err != nil {
		return context.Background()
	}

	var md = metadata.New(carrier)
	return metadata.NewOutgoingContext(ctx, md)
}

// If we cannot get ID from the distributed unique IDs generator, we generate a degraded, random one.
func (g *IDGenerator) degradedID() string {
	return "degraded-" + strconv.FormatUint(rand.Uint64(), 10)
}
