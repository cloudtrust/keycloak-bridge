package management

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=ManagementComponent=ManagementComponent,DBConfiguration=DBConfiguration,KeycloakClient=KeycloakClient,ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/pkg/management ManagementComponent,DBConfiguration,KeycloakClient,ConfigurationDBModule
//go:generate mockgen -destination=./mock/eventsdbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/keycloak-bridge/pkg/event EventsDBModule
//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/go-kit/kit/metrics Histogram
//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger
//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=Tracer=Tracer,Span=Span,SpanContext=SpanContext github.com/opentracing/opentracing-go Tracer,Span,SpanContext
