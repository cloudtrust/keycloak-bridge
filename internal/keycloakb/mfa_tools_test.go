package keycloakb

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/log"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestCheckRemovableMFA(t *testing.T) {
	var logger = log.NewNopLogger()

	var ctx = context.TODO()
	var myMFACredentialID = "cred-mfa1"
	var passwordCredentialID = "cred-password"
	var otherMFACredentialID = "cred-mfa2"
	var anyError = errors.New("any error")
	var credMyMFA = kc.CredentialRepresentation{ID: &myMFACredentialID, Type: ptr("any_mfa")}
	var credPassword = kc.CredentialRepresentation{ID: &passwordCredentialID, Type: ptr("password")}
	var credOtherMFA = kc.CredentialRepresentation{ID: &otherMFACredentialID, Type: ptr("any_mfa")}

	t.Run("Can't get credentials", func(t *testing.T) {
		var err = CheckRemovableMFA(ctx, myMFACredentialID, false, func() ([]kc.CredentialRepresentation, error) { return nil, anyError }, logger)
		assert.NotNil(t, err)
	})
	t.Run("Provided credential ID refers to a password", func(t *testing.T) {
		var err = CheckRemovableMFA(ctx, passwordCredentialID, false, func() ([]kc.CredentialRepresentation, error) {
			return []kc.CredentialRepresentation{credMyMFA, credPassword, credOtherMFA}, nil
		}, logger)
		assert.NotNil(t, err)
	})
	t.Run("Last MFA is not removable", func(t *testing.T) {
		var err = CheckRemovableMFA(ctx, myMFACredentialID, false, func() ([]kc.CredentialRepresentation, error) {
			return []kc.CredentialRepresentation{credMyMFA, credPassword}, nil
		}, logger)
		assert.NotNil(t, err)
	})
	t.Run("Last MFA is removable", func(t *testing.T) {
		var err = CheckRemovableMFA(ctx, myMFACredentialID, true, func() ([]kc.CredentialRepresentation, error) {
			return []kc.CredentialRepresentation{credMyMFA, credPassword}, nil
		}, logger)
		assert.Nil(t, err)
	})
	t.Run("Is removable", func(t *testing.T) {
		var err = CheckRemovableMFA(ctx, myMFACredentialID, false, func() ([]kc.CredentialRepresentation, error) {
			return []kc.CredentialRepresentation{credMyMFA, credPassword, credOtherMFA}, nil
		}, logger)
		assert.Nil(t, err)
	})
	t.Run("Unknown credential ID", func(t *testing.T) {
		var err = CheckRemovableMFA(ctx, "unknown-credential-id", false, func() ([]kc.CredentialRepresentation, error) {
			return []kc.CredentialRepresentation{credMyMFA, credPassword, credOtherMFA}, nil
		}, logger)
		assert.NotNil(t, err)
	})
}
