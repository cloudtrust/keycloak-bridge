# keycloak-bridge
Bridge services dedicated to keycloak interactions


## Launch

```bash
./script/build.sh --env <value>
``` 

```bash
./bin/keycloackBridge
``` 

When you launch the keycloack bridge, the parameters are read from ``` conf/ENV/keycloak_bridge.yaml ```.

For loading a different configuratiuon file launch the sevice with the following command: 

```bash
./bin/keycloackBridge --config-file "path/to/the/file.yaml".
``` 

