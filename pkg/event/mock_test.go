package event

//go:generate mockgen -destination=./mock/event.go -package=mock -mock_names=MuxComponent=MuxComponent,Component=Component,AdminComponent=AdminComponent,ConsoleModule=ConsoleModule,StatisticModule=StatisticModule github.com/cloudtrust/keycloak-bridge/pkg/event MuxComponent,Component,AdminComponent,ConsoleModule,StatisticModule
//go:generate mockgen -destination=./mock/dbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/common-service/database EventsDBModule
//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram,Metrics=Metrics github.com/cloudtrust/common-service/metrics Histogram,Metrics
//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/log Logger
//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=OpentracingClient=OpentracingClient,Finisher=Finisher github.com/cloudtrust/common-service/tracing OpentracingClient,Finisher
//go:generate mockgen -destination=./mock/tracking.go -package=mock -mock_names=SentryTracking=SentryTracking github.com/cloudtrust/common-service/tracking SentryTracking
