# Keycloak bridge [![Build Status][ci-img]][ci] [![Coverage Status][cov-img]][cov] [![GoDoc][godoc-img]][godoc] [![Go Report Card][report-img]][report] [![OpenTracing Badge][opentracing-img]][opentracing]

The keycloak bridge has one purpose, being a bridge for all the interactions with keycloak.

The service includes logging, metrics, tracing, and error tracking. The logs are written to stdout.
Metrics such as time tracking,... are collected and saved.

## Build
Build the service \<env>:

```bash
go build ./...
```

Note: \<env> is used for versioning.

## Configuration

Configuration is done with a YAML file, e.g. ```./configs/keycloak_bridge.yml```.
Default configurations are provided, that is if an entry is not present in the configuration file, it will be set to its default value.

The documentation for the [Debug](https://cloudtrust.github.io/doc/chapter-godevel/debugging.html) configuration is common to all microservices and is provided in the Cloudtrust Gitbook.

The configurations specific to the keycloak-bridge are described in the next sections.

### Component

For the component, the following parameters are available:

Key | Description | Default value
--- | ----------- | -------------
internal-http-host-port | HTTP server listening address | 0.0.0.0:8888
management-http-host-port | HTTP server listening address | 0.0.0.0:8877
account-http-host-port | HTTP server listening address | 0.0.0.0:8866
register-http-host-port | HTTP server listening address | 0.0.0.0:8855
mobile-http-host-port | HTTP server listening address | 0.0.0.0:8844


### Keycloak

Key | Description | Default value
--- | ----------- | -------------
keycloak-api-uri | Keycloak protocol:host:port | "http://127.0.0.1:8080"
keycloak-oidc-uri | Keycloak protocol:host:port (multiple value supported) | "http://127.0.0.1:8080 http://localhost:8080"
keycloak-timeout | Keycloak requests timeout in milliseconds | 5000


### Health check

Key | Description | Default value
--- | ----------- | -------------
livenessprobe-cache-duration | Health check results are not re-evaluated under this number of milliseconds | 500
livenessprobe-http-timeout | Timeout in milliseconds for HTTP checks | 900


### ENV variables

Some parameters can be overridden with following ENV variables:

ENV Variable | Parameter
--- | -----------
CT_BRIDGE_REGISTER_USERNAME | register-techuser-username
CT_BRIDGE_REGISTER_PASSWORD | register-techuser-password
CT_BRIDGE_REGISTER_CLIENT_ID | register-techuser-client-id
CT_BRIDGE_RECAPTCHA_SECRET | recaptcha-secret
CT_BRIDGE_TECHNICAL_USERNAME | technical-username
CT_BRIDGE_TECHNICAL_PASSWORD | technical-password
CT_BRIDGE_DB_CONFIG_USERNAME | db-config-username
CT_BRIDGE_DB_CONFIG_PASSWORD | db-config-password
CT_BRIDGE_DB_ARCHIVE_RW_USERNAME | db-archive-rw-username
CT_BRIDGE_DB_ARCHIVE_RW_PASSWORD | db-archive-rw-password
CT_BRIDGE_DB_ARCHIVE_AES_KEY | db-archive-aesgcm-key
CT_EVENT_PRODUCER_KAFKA_CLIENT_SECRET | kafka-cloudtrust-client-secret

## Usage

Launch the keycloak bridge:

```bash
./bin/keycloak_bridge --config-file <path/to/config/file.yml>
```

It is recommended to always provides an absolute path to the configuration file when the service is started, even though absolute and relative paths are supported.
If no configuration file is passed, the service will try to load the default config file at ```./configs/keycloak_bridge.yml```, and if it fails it launches the service with the default parameters.

### Monitoring of keycloak-bridge

An endpoint allows to get a status of the Bridge and its components health.
URL: ```http://{bridge.host}:{bridge.port}/health/check```

Status example:
```
{
 "name": "keycloak-bridge",
 "state": "DOWN",
 "details": [
  {
   "name": "Audit R/W",
   "type": "database",
   "state": "DOWN",
   "message": "bad connection"
  },
  {
   "name": "Config RO",
   "type": "database",
   "state": "UP",
   "connection": "established"
  },
  {
   "name": "Keycloak",
   "type": "http",
   "state": "DOWN",
   "message": "Can't hit target: Get http://127.0.0.1:8080: dial tcp 127.0.0.1:8080: connectex: No connection could be made because the target machine actively refused it."
  }
 ]
}
```

## Tests

Gomock is used to automatically generate mocks. See the Cloudtrust [Gitbook](https://cloudtrust.github.io/doc/chapter-godevel/testing.html) for more information.

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
