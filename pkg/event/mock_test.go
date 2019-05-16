package event

//go:generate mockgen -destination=./mock/event.go -package=mock -mock_names=MuxComponent=MuxComponent,Component=Component,AdminComponent=AdminComponent,ConsoleModule=ConsoleModule,StatisticModule=StatisticModule,EventsDBModule=EventsDBModule,Influx=Influx,DBEvents=DBEvents github.com/cloudtrust/keycloak-bridge/pkg/event MuxComponent,Component,AdminComponent,ConsoleModule,StatisticModule,EventsDBModule,Influx,DBEvents
//go:generate mockgen -destination=./mock/tracking.go -package=mock -mock_names=Sentry=Sentry github.com/cloudtrust/keycloak-bridge/pkg/event Sentry
//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=Tracer=Tracer,Span=Span,SpanContext=SpanContext github.com/opentracing/opentracing-go Tracer,Span,SpanContext
//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/go-kit/kit/metrics Histogram
//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger
