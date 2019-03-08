package middleware

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gbrlsnchs/jwt"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
)

// KeycloakClient is the interface of the keycloak client.
type KeycloakClient interface {
	VerifyToken(realmName string, accessToken string) error
}

// MakeHTTPOIDCTokenValidationMW retrieve the oidc token from the HTTP header 'Bearer' and
// check its validity for the Keycloak instance binded to the bridge.
// If there is no such header, the request is not allowed.
// If the token is validated, the following informations are added into the context:
//   - access_token: the recieved access token in raw format
//   - realm: realm name extracted from the Issuer information of the token
//   - username: username extracted from the token
func MakeHTTPOIDCTokenValidationMW(keycloakClient KeycloakClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var authorizationHeader = req.Header.Get("Authorization")

			if authorizationHeader == "" {
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Missing Authorization header"), w)
				return
			}

			var matched, _ = regexp.MatchString(`^Bearer *`, authorizationHeader)

			if !matched {
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Missing bearer token"), w)
				return
			}

			var splitToken = strings.Split(authorizationHeader, "Bearer ")
			var accessToken = splitToken[1]

			payload, _, err := jwt.Parse(accessToken)
			if err != nil {
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Invalid token"), w)
				return
			}

			var jot Token
			if err = jwt.Unmarshal(payload, &jot); err != nil {
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Invalid token"), w)
				return
			}

			var username = jot.Username
			var issuer = jot.JWT.Issuer
			var splitIssuer = strings.Split(issuer, "/auth/realms/")
			var realm = splitIssuer[1]

			if err = keycloakClient.VerifyToken(realm, accessToken); err != nil {
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Invalid token"), w)
				return
			}

			var ctx = context.WithValue(req.Context(), "access_token", accessToken)
			ctx = context.WithValue(ctx, "realm", realm)
			ctx = context.WithValue(ctx, "username", username)
			next.ServeHTTP(w, req.WithContext(ctx))

		})
	}
}

// Token is JWT token and the custom fields present in OIDC Token provided by Keycloak.
type Token struct {
	*jwt.JWT
	Username string `json:"preferred_username,omitempty"`
}

// MakeEndpointTokenForRealmMW makes a Endpoint middleware responsible to ensure
// the request is allowed to perform the operation for the current realm.
// During validation of JWT token, the realm of the token has been added into context.
// This MW ensure the realm of the Token match the target realm of the request.
func MakeEndpointTokenForRealmMW(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// Retrieve the realm of the context
			var realmAuthorized = ctx.Value("realm").(string)

			// Extract the target realm of the request
			var m = req.(map[string]string)
			var realmRequested = m["realm"]
			
			// Assert both realms match
			if realmAuthorized != realmRequested {
				//TODO create a specific error to map it on 403
				return ctx, fmt.Errorf("Invalid realm")
			}

			return next(ctx, req)
		}
	}
}
