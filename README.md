# Keycloak bridge [![Build Status][ci-img]][ci] [![Coverage Status][cov-img]][cov] [![GoDoc][godoc-img]][godoc] [![Go Report Card][report-img]][report] [![OpenTracing Badge][opentracing-img]][opentracing]

The keycloak bridge has two purposes. All our interactions (administration) with keycloak pass through it, and keycloak sends all events (i.e. login, user creation,...) to the bridge, so that they can be processed, stored,...

The service includes logging, metrics, tracing, and error tracking. The logs are written to stdout.
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

Configuration is done with a YAML file, e.g. ```./configs/keycloak_bridge.yml```.
Default configurations are provided, that is if an entry is not present in the configuration file, it will be set to its default value.

The documentation for the [Influx](https://cloudtrust.github.io/doc/chapter-godevel/instrumenting.html), [Sentry](https://cloudtrust.github.io/doc/chapter-godevel/tracking.html), [Jaeger](https://cloudtrust.github.io/doc/chapter-godevel/tracing.html) and [Debug](https://cloudtrust.github.io/doc/chapter-godevel/debugging.html) configuration are common to all microservices and is provided in the Cloudtrust Gitbook.

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
./bin/keycloak_bridge --config-file <path/to/config/file.yml>
```

It is recommended to always provides an absolute path to the configuration file when the service is started, even though absolute and relative paths are supported.
If no configuration file is passed, the service will try to load the default config file at ```./configs/keycloak_bridge.yml```, and if it fails it launches the service with the default parameters.

### Keycloak events

The keycloak event-emitter module sends all events to the bridge's event endpoint. The event emitter use HTTP with flatbuffers.

## About monitoring

Each gRPC or HTTP request will trigger a set of operations that are going to be logged, measured, tracked and traced. For those information to be usable, we must be able to link the logs, metrics, traces and error report together. We achieve that with a unique correlation ID. For a given request, the same correlation ID will appear on the logs, metrics, traces and error report.

Note: InfluxDB indexes tags, so we put the correlation ID as tags to speed up queries. To query a tag, do not forget to simple quote it, otherwise it always returns empty results.

```sql
select * from "<measurement>" where "correlation_id" = '<correlation_id>';
```

Note: In Jaeger UI, to search traces with a given correlation ID you must copy the following in the "Tags" box:

```sql
correlation_id:<correlation_id>
```

## Tests

Gomock is used to automatically genarate mocks. See the Cloudtrust [Gitbook](https://cloudtrust.github.io/doc/chapter-godevel/testing.html) for more information.

The unit tests don't cover:

- keycloak_bridge (```./cmd/keycloak_bridge.go```)

The first two are provided as example.

The ```keycloak_bridge.go``` is mostly just the main function doing all the wiring, it is difficult to test it with unit tests. It is covered by our integration tests.

[ci-img]: https://travis-ci.org/cloudtrust/keycloak-bridge.svg?branch=master
[ci]: https://travis-ci.org/cloudtrust/keycloak-bridge
[cov-img]: https://coveralls.io/repos/github/cloudtrust/keycloak-bridge/badge.svg?branch=master
[cov]: https://coveralls.io/github/cloudtrust/keycloak-bridge?branch=master
[godoc-img]: https://godoc.org/github.com/cloudtrust/keycloak-bridge?status.svg
[godoc]: https://godoc.org/github.com/cloudtrust/keycloak-bridge
[report-img]: https://goreportcard.com/badge/github.com/cloudtrust/keycloak-bridge
[report]: https://goreportcard.com/report/github.com/cloudtrust/keycloak-bridge
[opentracing-img]: https://img.shields.io/badge/OpenTracing-enabled-blue.svg
[opentracing]: http://opentracing.io
