package keycloakb

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestToDetails(t *testing.T) {
	var accredType = "BASIC"
	var now = time.Now().Unix()
	var expiry = expiryDate(50)
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
		var accreds = []string{
			formatAccreditation("ONE", 10),
			formatAccreditation("TWO", 6),
			formatAccreditation("THREE", 20),
		}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.True(t, ap.HasActiveAccreditations())
	})
	t.Run("active & non-active accreditations", func(t *testing.T) {
		var accreds = []string{
			formatAccreditation("ONE", -5),
			formatAccreditation("TWO", 10),
			formatRevokedAccreditation("THREE", 5),
		}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.True(t, ap.HasActiveAccreditations())
	})
	t.Run("only revoked accreditation", func(t *testing.T) {
		var accreds = []string{
			formatRevokedAccreditation("ONE", -5),
			formatRevokedAccreditation("ONE", 10),
		}
		var ap, _ = NewAccreditationsProcessor(accreds)
		assert.False(t, ap.HasActiveAccreditations())
	})
	t.Run("only expired accreditation", func(t *testing.T) {
		var accreds = []string{formatAccreditation("ONE", -5)}
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
		var accreds = []string{
			formatAccreditation("ONE", -5),
			formatAccreditation("TWO", -4),
			formatAccreditation("THREE", 1),
			formatAccreditation("THREE", 5),
		}
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
	var accreds = []string{
		formatAccreditation("ONE", -5),
		formatAccreditation("TWO", 10),
		formatAccreditation("THREE", 5),
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
	creationDate := createRelativeDate(3)
	expectedCreationMillis1 := fmt.Sprintf("%d", creationDate.UnixNano()/int64(time.Millisecond))
	validity := "4y"
	_ = ap.AddAccreditation(creationDate, "AAA", validity)
	var res = ap.ToKeycloak()
	assert.Len(t, res, 1)

	expectedExpiryDate1 := validation.AddLargeDuration(creationDate, validity).UTC().Format("02.01.2006")
	assert.Contains(t, res[0], `"AAA"`)
	assert.Contains(t, res[0], `"`+expectedExpiryDate1+`"`)
	assert.NotContains(t, res[0], `"revoked"`)

	//Add second accreditation, same type
	creationDate = createRelativeDate(4)
	expectedCreationMillis2 := fmt.Sprintf("%d", creationDate.UnixNano()/int64(time.Millisecond))
	validity = "7y"
	_ = ap.AddAccreditation(creationDate, "AAA", validity)
	res = ap.ToKeycloak()
	assert.Len(t, res, 2)

	expectedExpiryDate2 := validation.AddLargeDuration(creationDate, validity).UTC().Format("02.01.2006")

	// First accreditation became revoked
	assert.Contains(t, res, `{"type":"AAA","creationMillis":`+expectedCreationMillis1+`,"expiryDate":"`+expectedExpiryDate1+`","revoked":true}`)
	assert.Contains(t, res, `{"type":"AAA","creationMillis":`+expectedCreationMillis2+`,"expiryDate":"`+expectedExpiryDate2+`"}`)

	// Add third accreditation, new type
	creationDate = createRelativeDate(5)
	expectedCreationMillis3 := fmt.Sprintf("%d", creationDate.UnixNano()/int64(time.Millisecond))
	validity = "5y"
	_ = ap.AddAccreditation(creationDate, "BBB", validity)
	res = ap.ToKeycloak()
	assert.Len(t, res, 3)
	expectedExpiryDate3 := validation.AddLargeDuration(creationDate, validity).UTC().Format("02.01.2006")
	assert.Contains(t, res, `{"type":"BBB","creationMillis":`+expectedCreationMillis3+`,"expiryDate":"`+expectedExpiryDate3+`"}`)
}

func formatRevokedAccreditation(accredType string, yearsOfValidity int) string {
	return `{"type":"` + accredType + `","expiryDate":"` + expiryDate(time.Duration(yearsOfValidity)) + `","revoked":true}`
}

func formatAccreditation(accredType string, yearsOfValidity int) string {
	return `{"type":"` + accredType + `","expiryDate":"` + expiryDate(time.Duration(yearsOfValidity)) + `"}`
}

func expiryDate(years time.Duration) string {
	timeFormat := "02.01.2006"
	return createRelativeDate(years).Format(timeFormat)
}

func createRelativeDate(years time.Duration) time.Time {
	return time.Now().Add(years * 365 * 24 * time.Hour)
}
