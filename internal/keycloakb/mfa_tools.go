package keycloakb

import (
	"context"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

var notMFATypes = map[string]bool{"password": true, "password-history": true}

// CheckRemovableMFA checks if a given credential is removable (owned by user and not the password credential)
func CheckRemovableMFA(ctx context.Context, credentialID string, lastMFARemovable bool, getCredentials func() ([]kc.CredentialRepresentation, error), logger Logger) error {
	credentialsKc, err := getCredentials()
	if err != nil {
		logger.Warn(ctx, "msg", "Can't get credentials", "err", err.Error())
		return err
	}
	var found bool
	var foundRemainingMFA bool
	for _, credential := range credentialsKc {
		if credential.ID != nil && *credential.ID != credentialID {
			if value, ok := notMFATypes[*credential.Type]; !ok || !value {
				foundRemainingMFA = true
			}
		} else if *credential.Type == "password" {
			logger.Info(ctx, "msg", "Can't remove password credential")
			return errorhandler.CreateBadRequestError("cantRemovePassword")
		} else {
			found = true
		}
	}
	if !found {
		logger.Info(ctx, "msg", "Can't remove unknown credential")
		return errorhandler.CreateNotFoundError("credential")
	}
	if lastMFARemovable || foundRemainingMFA {
		return nil
	}
	logger.Info(ctx, "msg", "Not enough MFA registered: can't remove any credential")
	return errorhandler.CreateBadRequestError("notEnoughMFA")
}
