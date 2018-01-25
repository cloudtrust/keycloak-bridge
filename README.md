
[![Coverage Status](https://coveralls.io/repos/github/cloudtrust/keycloak-bridge/badge.svg?branch=master)](https://coveralls.io/github/cloudtrust/keycloak-bridge?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/cloudtrust/keycloak-bridge)](https://goreportcard.com/report/github.com/cloudtrust/keycloak-bridge)

# keycloak-bridge
Bridge services dedicated to keycloak interactions


## Build

```bash
./script/build.sh --env <value>
``` 
## Launch

```bash
./bin/keycloackBridge
``` 

When you launch the keycloack bridge, the parameters are read from ```./conf/ENV/keycloak_bridge.yaml ```.

For loading a different configuration file, launch the sevice with the following command: 

```bash
./bin/keycloackBridge --config-file "path/to/the/file.yaml".
``` 

