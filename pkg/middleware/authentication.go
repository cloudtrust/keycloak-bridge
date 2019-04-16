package middleware

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gbrlsnchs/jwt"
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
func MakeHTTPOIDCTokenValidationMW(keycloakClient KeycloakClient, logger log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var authorizationHeader = req.Header.Get("Authorization")

			if authorizationHeader == "" {
				logger.Log("Authorisation Error", "Missing Authorization header")
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Missing Authorization header"), w)
				return
			}

			var matched, _ = regexp.MatchString(`^[Bb]earer *`, authorizationHeader)

			if !matched {
				logger.Log("Authorisation Error", "Missing bearer token")
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Missing bearer token"), w)
				return
			}

			var splitToken = strings.Split(authorizationHeader, "Bearer ")

			if len(splitToken) < 2 {
				splitToken = strings.Split(authorizationHeader, "bearer ")
			}

			var accessToken = splitToken[1]

			payload, _, err := jwt.Parse(accessToken)
			if err != nil {
				logger.Log("Authorisation Error", err)
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Invalid token"), w)
				return
			}

			var jot Token
			if err = jwt.Unmarshal(payload, &jot); err != nil {
				logger.Log("Authorisation Error", err)
				httpErrorHandler(context.TODO(), http.StatusForbidden, fmt.Errorf("Invalid token"), w)
				return
			}

			var username = jot.Username
			var issuer = jot.Issuer
			var splitIssuer = strings.Split(issuer, "/auth/realms/")
			var realm = splitIssuer[1]

			if err = keycloakClient.VerifyToken(realm, accessToken); err != nil {
				logger.Log("Authorisation Error", err)
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
// We need to define our own structure as the library define aud as a string instead of a string array.
type Token struct {
	hdr            *header
	Issuer         string   `json:"iss,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Audience       []string `json:"aud,omitempty"`
	ExpirationTime int64    `json:"exp,omitempty"`
	NotBefore      int64    `json:"nbf,omitempty"`
	IssuedAt       int64    `json:"iat,omitempty"`
	ID             string   `json:"jti,omitempty"`
	Username       string   `json:"preferred_username,omitempty"`
}

type header struct {
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}
