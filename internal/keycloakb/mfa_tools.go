package keycloakb

import (
	"context"

	errorhandler "github.com/cloudtrust/common-service/errors"
	kc "github.com/cloudtrust/keycloak-client"
)

var notMFATypes = map[string]bool{"password": true, "password-history": true}

// CheckRemovableMFA checks if a given credential is removable (owned by user and not the password credential)
func CheckRemovableMFA(ctx context.Context, credentialID string, getCredentials func() ([]kc.CredentialRepresentation, error), logger Logger) error {
	credentialsKc, err := getCredentials()
	if err != nil {
		logger.Warn(ctx, "msg", "Can't get credentials", "err", err.Error())
		return err
	}

	for _, credential := range credentialsKc {
		if *credential.ID == credentialID {
			if *credential.Type == "password" {
				logger.Info(ctx, "msg", "Can't remove password credential")
				return errorhandler.CreateBadRequestError("cantRemovePassword")
			} else {
				return nil
			}
		}
	}
	logger.Info(ctx, "msg", "Can't remove unknown credential")
	return errorhandler.CreateNotFoundError("credential")
}
