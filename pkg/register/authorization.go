package register

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
)

const (
	regexpBasicAuth = `^[Bb]asic (.+)$`
	regExpRecaptcha = `^([\w\d]+):secret=(.+),token=(.+)$`
)

type recaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// MakeHTTPRecaptchaValidationMW retrieves the recaptcha code and checks its validity
func MakeHTTPRecaptchaValidationMW(recaptchaURL string, logger log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var authorizationHeader = req.Header.Get("Authorization")
			var ctx = context.TODO()

			if authorizationHeader == "" {
				logger.Info(ctx, "Authorization Error", "Missing Authorization header")
				httpErrorHandler(ctx, http.StatusForbidden, errors.New(errorhandler.MsgErrMissingParam+"."+errorhandler.AuthHeader), w)
				return
			}

			var r = regexp.MustCompile(regexpBasicAuth)
			var match = r.FindStringSubmatch(authorizationHeader)
			if match == nil {
				logger.Info(ctx, "Authorization Error", "Missing basic token")
				httpErrorHandler(ctx, http.StatusForbidden, errors.New(errorhandler.MsgErrMissingParam+"."+errorhandler.BasicToken), w)
				return
			}

			// Decode base 64 (RegExp matched: we got exactly 2 values. match[0] is the global matched string, match[1] is the first group)
			decodedToken, err := base64.StdEncoding.DecodeString(match[1])
			if err != nil {
				logger.Info(ctx, "Authorization Error", "Invalid base64 token")
				httpErrorHandler(ctx, http.StatusForbidden, errors.New(errorhandler.MsgErrInvalidParam+"."+errorhandler.Token), w)
				return
			}

			// Extract username & password values
			r = regexp.MustCompile(regExpRecaptcha)
			match = r.FindStringSubmatch(string(decodedToken))
			if match == nil {
				logger.Info(ctx, "Authorization Error", "Invalid token format (recaptcha:secret={secret},token={token})")
				httpErrorHandler(ctx, http.StatusForbidden, errors.New(errorhandler.MsgErrInvalidParam+"."+errorhandler.Token), w)
				return
			}

			if !checkRecaptcha(ctx, recaptchaURL, match[2], match[3], logger) {
				httpErrorHandler(ctx, http.StatusForbidden, errors.New(errorhandler.MsgErrInvalidParam+"."+errorhandler.Token), w)
				return
			}

			next.ServeHTTP(w, req)
		})
	}
}

func httpErrorHandler(_ context.Context, statusCode int, err error, w http.ResponseWriter) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	w.Write([]byte(errorhandler.GetEmitter() + "." + err.Error()))
}

func checkRecaptcha(ctx context.Context, recaptchaURL string, secret string, token string, logger log.Logger) bool {
	var parameters = fmt.Sprintf("secret=%s&response=%s", url.QueryEscape(secret), url.QueryEscape(token))
	var resp, err = http.Post(recaptchaURL, "application/x-www-form-urlencoded", strings.NewReader(parameters))
	if err != nil {
		logger.Warn(ctx, "msg", "Can't validate recaptcha token", "err", err.Error())
		return false
	}
	if resp.StatusCode != http.StatusOK {
		logger.Warn(ctx, "msg", fmt.Sprintf("Recaptcha validation failed: http status %d", resp.StatusCode))
		return false
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	var recaptchaResponse recaptchaResponse
	err = json.Unmarshal(buf.Bytes(), &recaptchaResponse)
	if err != nil {
		logger.Warn(ctx, "msg", "Recaptcha validation: can't deserialize response", "response", buf.Bytes())
		return false
	}

	if !recaptchaResponse.Success {
		logger.Warn(ctx, "msg", "Recaptcha validation: invalid token", "cause", recaptchaResponse.ErrorCodes)
	}

	return recaptchaResponse.Success
}

type authorizationComponentMW struct {
	logger log.Logger
	next   Component
}

// MakeAuthorizationRegisterComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationRegisterComponentMW(logger log.Logger) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			logger: logger,
			next:   next,
		}
	}
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) RegisterUser(ctx context.Context, realmName string, user apiregister.User) (string, error) {
	return c.next.RegisterUser(ctx, realmName, user)
}
