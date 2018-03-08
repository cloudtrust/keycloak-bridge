# Keycloak bridge [![Build Status](https://travis-ci.org/cloudtrust/keycloak-bridge.svg?branch=master)](https://travis-ci.org/cloudtrust/keycloak-bridge) [![Coverage Status](https://coveralls.io/repos/github/cloudtrust/keycloak-bridge/badge.svg?branch=master)](https://coveralls.io/github/cloudtrust/keycloak-bridge?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/cloudtrust/keycloak-bridge)](https://goreportcard.com/report/github.com/cloudtrust/keycloak-bridge) [![OpenTracing Badge](https://img.shields.io/badge/OpenTracing-enabled-blue.svg)](http://opentracing.io)

The keycloak bridge has two purposes. All our interactions with keycloak pass through it, and keycloak sends all events (i.e. login, user creation,...) to the bridge, so that they can be processed, stored,...

The service includes logging, metrics, tracing, and error tracking. The logs are written to stdout and Redis in Logstash format for processing with the Elastic Stack.
Metrics such as time tracking,... are collected and saved to an InfluxDB Time Series Database.
Jaeger is used for distributed tracing and error tracking is managed with Sentry.

## Build
The service uses [FlatBuffers](https://google.github.io/flatbuffers/) for data serialisation. Make sure you have FlatBuffers installed and up to date with ```flatc --version```. It was tested with "flatc version 1.8.0 (Nov 22 2017)".

Build the service for the environment \<env>: 
```bash
./scripts/build.sh --env <env>
```
Note: \<env> is used for versioning. 

## Container
The keycloak bridge is intended to run in a container with keycloak (including the [event-emitter](https://github.com/cloudtrust/event-emitter) module).
See the repository [keycloak-service](https://github.com/cloudtrust/keycloak-service).

## Configuration
Configuration is done with a YAML file, e.g. ```./conf/DEV/keycloakd.yml```.
Default configurations are provided, that is if an entry is not present in the configuration file, it will be set to its default value.

The documentation for the [Redis](https://cloudtrust.github.io/doc/chapter-godevel/logging.html), [Influx](https://cloudtrust.github.io/doc/chapter-godevel/instrumenting.html), [Sentry](https://cloudtrust.github.io/doc/chapter-godevel/tracking.html), [Jaeger](https://cloudtrust.github.io/doc/chapter-godevel/tracing.html) and [Debug](https://cloudtrust.github.io/doc/chapter-godevel/debugging.html) configuration are common to all microservices and is provided in the Cloudtrust Gitbook.

The configurations specific to the keycloak-bridge are described in the next sections.

### Component
For the component, the following parameters are available:

Key | Description | Default value 
--- | ----------- | ------------- 
component-name | name of the component | keycloak-bridge 
component-http-host-port | HTTP server listening address | 0.0.0.0:8888 
component-grpc-host-port | gRPC server listening address  | 0.0.0.0:5555 

### Flaki
Key | Description | Default value 
--- | ----------- | ------------- 
flaki-host-port | Flaki service host:port | ""

The [flaki-service](https://github.com/cloudtrust/flaki-service) is used to obtain unique IDs in a distributed system.

### Keycloak
Key | Description | Default value 
--- | ----------- | ------------- 
keycloak-host-port | Keycloak host:port | "127.0.0.1:8080"
keycloak-username | Keycloak username | ""
keycloak-password | Keycloak password | ""
keycloak-timeout-ms | Keycloak requests timeout in milliseconds | 5000

## Usage
Launch the keycloak bridge:
```bash
./bin/keycloakd --config-file <path/to/config/file.yml>
```
It is recommended to always provides an absolute path to the configuration file when the service is started, even though absolute and relative paths are supported.
If no configuration file is passed, the service will try to load the default config file at ```./conf/DEV/keycloakd.yml```, and if it fails it launches the service with the default parameters.

### Keycloak events
The keycloak event-emitter module sends all events to the bridge's event endpoint. The event emitter use HTTP with flatbuffers.

### gRPC and HTTP clients
All applications can interact with the bridge using either HTTP or gRPC. 
The applications need to implement its own client. The Flatbuffer schema is available in ``pkg/user/flatbuffer/user.fbs`
There is an example in the directory `client`. 

### Health
The service exposes HTTP routes to monitor the application health.
See the cloudtrust [gitbook](https://cloudtrust.github.io/doc/chapter-godevel/health_route.html) for more details.

## About monitoring
Each gRPC or HTTP request will trigger a set of operations that are going to be logged, measured, tracked and traced. For those information to be usable, we must be able to link the logs, metrics, traces and error report together. We achieve that with a unique correlation ID. For a given request, the same correlation ID will appear on the logs, metrics, traces and error report.

Note: InfluxDB indexes tags, so we put the correlation ID as tags to speed up queries. To query a tag, do not forget to simple quote it, otherwise it always returns empty results.
```
select * from "<measurement>" where "correlation_id" = '<correlation_id>';
```

Note: In Jaeger UI, to search traces with a given correlation ID you must copy the following in the "Tags" box: 
```
correlation_id:<correlation_id>
```

## Tests

Gomock is used to automatically genarate mocks. See the Cloudtrust [Gitbook](https://cloudtrust.github.io/doc/chapter-godevel/testing.html) for more information.

The unit tests don't cover:
- http client example (```./client/http/http.go```)
- grpc client example (```./client/grpc/grpc.go```)
- keycloakd  (```./cmd/keycloakd.go```)

The first two are provided as example.

The ```keycloakd.go``` is mostly just the main function doing all the wiring, it is difficult to test it with unit tests. It is covered by our integration tests.

## Limitations

The Redis connection does not handle errors well: if there is a problem, it is closed forever. We will implement our own redis client later, because we need load-balancing and circuit-breaking.