# keycloak-bridge
Bridge services dedicated to keycloak interactions

# BUILD

```bash
go build  -ldflags "-X main.VERSION=0.0.1" daemon/keycloakd.go
```

# RUN

```Bash
keycloakd --config-file="./conf/DEV/keycloak_bridge.yaml"
```