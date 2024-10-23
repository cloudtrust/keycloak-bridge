package keycloakb

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestToDetails(t *testing.T) {
	var accredType = "BASIC"
	var now = time.Now().Unix()
	var expiry = "31.12.2099"
	var accred = AccreditationRepresentation{
		Type:           &accredType,
		CreationMillis: &now,
		ExpiryDate:     &expiry,
	}
	assert.Len(t, accred.ToDetails(), 3)

	accred.CreationMillis = nil
	assert.Len(t, accred.ToDetails(), 2)
}

func TestHasActiveAccreditations(t *testing.T) {
	t.Run("only active accreditations", func(t *testing.T) {
		var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2040"}`,
			`{"type":"TWO","expiryDate":"01.01.2036"}`,
			`{"type":"THREE","expiryDate":"01.01.2050"}`,
		}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.True(t, ap.HasActiveAccreditations())
	})
	t.Run("active & non-active accreditations", func(t *testing.T) {
		var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2015"}`,
			`{"type":"TWO","expiryDate":"01.01.2036"}`,
			`{"type":"THREE","expiryDate":"01.01.2025","revoked":"true"}`,
		}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.True(t, ap.HasActiveAccreditations())
	})
	t.Run("only revoked accreditation", func(t *testing.T) {
		var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2015","revoked":"true"}`,
			`{"type":"TWO","expiryDate":"01.01.2036","revoked":"true"}`,
		}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.False(t, ap.HasActiveAccreditations())
	})
	t.Run("only expired accreditation", func(t *testing.T) {
		var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2015"}`}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.False(t, ap.HasActiveAccreditations())
	})
	t.Run("no accreditation", func(t *testing.T) {
		var accreds = []string{}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.False(t, ap.HasActiveAccreditations())
	})
}

func TestRevokeAccreditations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	t.Run("No existing accreditations", func(t *testing.T) {
		var user = kc.UserRepresentation{}
		var updated = RevokeAccreditations(&user, func(AccreditationRepresentation) {})
		assert.Len(t, user.GetAttribute(constants.AttrbAccreditations), 0)
		assert.False(t, updated)
	})
	t.Run("Nothing changes", func(t *testing.T) {
		var user = kc.UserRepresentation{}
		var accreds = []string{"a", "b", `{"type":"ONE", "expiryDate":"01.01.2015", "creationMillis":123456789, "revoked":true}`}
		user.SetAttribute(constants.AttrbAccreditations, accreds)
		var updated = RevokeAccreditations(&user, func(AccreditationRepresentation) {})
		assert.Equal(t, accreds, user.GetAttribute(constants.AttrbAccreditations))
		assert.False(t, updated)
	})
	t.Run("Revoke one accreditation", func(t *testing.T) {
		var user = kc.UserRepresentation{}
		var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2015"}`,
			`{"type":"TWO","expiryDate":"01.01.2016"}`,
			`{"type":"THREE","expiryDate":"01.01.2025"}`,
			`{"type":"THREE","expiryDate":"01.01.2032"}`}
		user.SetAttribute(constants.AttrbAccreditations, accreds)
		var updated = RevokeAccreditations(&user, func(AccreditationRepresentation) {})
		assert.True(t, updated)
		userAccreds := user.GetAttribute(constants.AttrbAccreditations)
		for _, userAccred := range userAccreds {
			if strings.Contains(userAccred, "THREE") {
				assert.Contains(t, userAccred, `"revoked":true`)
			} else {
				assert.NotContains(t, userAccred, `"revoked":true`)
			}
		}
	})
}

func TestRevokeTypes(t *testing.T) {
	var accreds = []string{`{"type":"ONE","expiryDate":"01.01.2015"}`,
		`{"type":"TWO","expiryDate":"01.01.2036"}`,
		`{"type":"THREE","expiryDate":"01.01.2025"}`,
	}
	var ap, _ = NewAccreditationsProcessor(accreds)
	t.Run("Revoke 2 types", func(t *testing.T) {
		ap.RevokeTypes([]string{"THREE", "ONE"}, func(AccreditationRepresentation) {})
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
		ap.RevokeTypes([]string{"TWO"}, func(AccreditationRepresentation) {})
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

	//Add first accreditation
	creationDate, _ := time.Parse("2006-Jan-02", "2027-Jan-01")
	fmt.Println(creationDate)
	_ = ap.AddAccreditation(creationDate, "AAA", "4y")
	var res = ap.ToKeycloak()
	assert.Len(t, res, 1)

	assert.Contains(t, res[0], `"AAA"`)
	assert.Contains(t, res[0], `"01.01.2031"`)
	assert.NotContains(t, res[0], `"revoked"`)

	//Add second accreditation, same type
	creationDate, _ = time.Parse("2006-Jan-02", "2025-Jan-01")
	_ = ap.AddAccreditation(creationDate, "AAA", "7y")
	res = ap.ToKeycloak()
	assert.Len(t, res, 2)

	// First accreditation became revoked
	assert.Contains(t, res, `{"type":"AAA","creationMillis":1798761600000,"expiryDate":"01.01.2031","revoked":true}`)
	assert.Contains(t, res, `{"type":"AAA","creationMillis":1735689600000,"expiryDate":"01.01.2032"}`)

	// Add third accreditation, new type
	creationDate, _ = time.Parse("2006-Jan-02", "2028-Apr-17")
	_ = ap.AddAccreditation(creationDate, "BBB", "5y")
	res = ap.ToKeycloak()
	assert.Len(t, res, 3)
	assert.Contains(t, res, `{"type":"BBB","creationMillis":1839542400000,"expiryDate":"17.04.2033"}`)
}
