package keycloakb

import (
	"strings"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	"github.com/cloudtrust/common-service/v2/configuration"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func createRealmAdminCred(typeValue, validity, condition string) configuration.RealmAdminAccreditation {
	return configuration.RealmAdminAccreditation{
		Type:      &typeValue,
		Validity:  &validity,
		Condition: &condition,
	}
}

const (
	duration1 = "2y"
	duration2 = "1w"
	duration3 = "6m"
)

func createRealmAdminConfig(condition string) configuration.RealmAdminConfiguration {
	var otherCondition = "no-" + condition
	var accreds = []configuration.RealmAdminAccreditation{
		createRealmAdminCred("SHADOW1", duration1, condition),
		createRealmAdminCred("SHADOW2", "1y", otherCondition),
		createRealmAdminCred("SHADOW3", duration2, condition),
		createRealmAdminCred("SHADOW4", "3y", otherCondition),
		createRealmAdminCred("SHADOW5", duration3, condition),
	}
	return configuration.RealmAdminConfiguration{Accreditations: accreds}
}

func TestRevokeAccreditations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var user = kc.UserRepresentation{}

	t.Run("No existing accreditations", func(t *testing.T) {
		var updated = RevokeAccreditations(&user)
		assert.Len(t, user.GetAttribute(constants.AttrbAccreditations), 0)
		assert.False(t, updated)
	})
	t.Run("Nothing changes", func(t *testing.T) {
		var accreds = []string{"a", "b", `{"type":"ONE", "expiryDate":"01.01.2015", "creationMillis":123456789, "revoked":true}`}
		user.SetAttribute(constants.AttrbAccreditations, accreds)
		var updated = RevokeAccreditations(&user)
		assert.Equal(t, accreds, user.GetAttribute(constants.AttrbAccreditations))
		assert.False(t, updated)
	})
	t.Run("Revoke one accreditation", func(t *testing.T) {
		var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2015"}`,
			`{"type":"TWO","expiryDate":"01.01.2016"}`,
			`{"type":"THREE","expiryDate":"01.01.2025"}`,
			`{"type":"THREE","expiryDate":"01.01.2032"}`}
		user.SetAttribute(constants.AttrbAccreditations, accreds)
		var updated = RevokeAccreditations(&user)
		assert.Equal(t, accreds[0], user.GetAttribute(constants.AttrbAccreditations)[0])
		assert.Equal(t, accreds[1], user.GetAttribute(constants.AttrbAccreditations)[1])
		assert.NotEqual(t, accreds[2], user.GetAttribute(constants.AttrbAccreditations)[2])
		assert.True(t, updated)
	})
}

func TestRevokeTypes(t *testing.T) {
	var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2015"}`,
		`{"type":"TWO","expiryDate":"01.01.2036"}`,
		`{"type":"THREE","expiryDate":"01.01.2025"}`,
	}
	var ap, _ = NewAccreditationsProcessor(accreds)
	t.Run("Revoke 2 types", func(t *testing.T) {
		ap.RevokeTypes([]string{"THREE", "ONE"})
		var res = ap.ToKeycloak()
		assert.Len(t, res, len(accreds))

		for _, accredJSON := range res {
			// ONE is already expired... should not be explicitly revoked
			if strings.Contains(accredJSON, "THREE") {
				assert.Contains(t, accredJSON, `"revoked":true`)
			} else {
				assert.NotContains(t, accredJSON, `"revoked":true`)
			}
		}
	})
	t.Run("Revoke TWO", func(t *testing.T) {
		ap.RevokeTypes([]string{"TWO"})
		var res = ap.ToKeycloak()
		assert.Len(t, res, len(accreds))

		for _, accredJSON := range res {
			// ONE is already expired... should not be explicitly revoked
			if strings.Contains(accredJSON, "ONE") {
				assert.NotContains(t, accredJSON, `"revoked":true`)
			} else {
				assert.Contains(t, accredJSON, `"revoked":true`)
			}
		}
	})
}

func TestAddAccreditation(t *testing.T) {
	var ap, _ = NewAccreditationsProcessor(nil)

	t.Run("Add first accreditation", func(t *testing.T) {
		ap.AddAccreditation("AAA", "01.01.2031")
		var res = ap.ToKeycloak()
		assert.Len(t, res, 1)

		assert.Contains(t, res[0], `"AAA"`)
		assert.Contains(t, res[0], `"01.01.2031"`)
		assert.NotContains(t, res[0], `"revoked"`)
	})
	t.Run("Add second accreditation, same type", func(t *testing.T) {
		ap.AddAccreditation("AAA", "01.01.2032")
		var res = ap.ToKeycloak()
		assert.Len(t, res, 2)

		// First accreditation became revoked
		assert.Contains(t, res[0], `"AAA"`)
		assert.Contains(t, res[0], `"01.01.2031"`)
		assert.Contains(t, res[0], `"revoked"`)

		assert.Contains(t, res[1], `"AAA"`)
		assert.Contains(t, res[1], `"01.01.2032"`)
		assert.NotContains(t, res[1], `"revoked"`)
	})
	t.Run("Add third accreditation, new type", func(t *testing.T) {
		ap.AddAccreditation("BBB", "01.01.2033")
		var res = ap.ToKeycloak()
		assert.Len(t, res, 3)
	})
}
