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

