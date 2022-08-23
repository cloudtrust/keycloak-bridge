package keycloakb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
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

	//Add first accreditation
	creationDate, _ := time.Parse("2006-Jan-02", "2027-Jan-01")
	fmt.Println(creationDate)
	ap.AddAccreditation(creationDate, "AAA", "4y")
	var res = ap.ToKeycloak()
	assert.Len(t, res, 1)

	assert.Contains(t, res[0], `"AAA"`)
	assert.Contains(t, res[0], `"01.01.2031"`)
	assert.NotContains(t, res[0], `"revoked"`)

	//Add second accreditation, same type
	creationDate, _ = time.Parse("2006-Jan-02", "2025-Jan-01")
	ap.AddAccreditation(creationDate, "AAA", "7y")
	res = ap.ToKeycloak()
	assert.Len(t, res, 2)

	// First accreditation became revoked
	assert.Contains(t, res, `{"type":"AAA","creationMillis":1798761600000,"expiryDate":"01.01.2031","revoked":true}`)
	assert.Contains(t, res, `{"type":"AAA","creationMillis":1735689600000,"expiryDate":"01.01.2032"}`)

	// Add third accreditation, new type
	creationDate, _ = time.Parse("2006-Jan-02", "2028-Apr-17")
	ap.AddAccreditation(creationDate, "BBB", "5y")
	res = ap.ToKeycloak()
	assert.Len(t, res, 3)
	assert.Contains(t, res, `{"type":"BBB","creationMillis":1839542400000,"expiryDate":"17.04.2033"}`)
}

func TestEvaluateAccreditations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccreditationsClient := mock.NewAccreditationsServiceClient(mockCtrl)

	realmName := "testRealm"
	userID := "testUserID"
	accreds := []string{`{"type":"ONE","expiryDate":"01.01.2040"}`,
		`{"type":"TWO","expiryDate":"01.01.2036"}`,
		`{"type":"THREE","expiryDate":"01.01.2050"}`,
	}
	expectedError := errors.New("Test error")
	ctx := context.Background()

	var fieldsComparator = fields.NewFieldsComparator().
		CompareValueAndFunctionForUpdate(fields.FirstName, ptr("new firstname"), func(f fields.Field) []string {
			return []string{"old firstname"}
		}).
		CompareValueAndFunctionForUpdate(fields.LastName, ptr("new lastname"), func(f fields.Field) []string {
			return []string{"old lastname"}
		})

	evaluator := NewAccreditationsEvaluator(mockAccreditationsClient, log.NewNopLogger())

	t.Run("failure", func(t *testing.T) {
		mockAccreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return([]string{"ONE"}, expectedError)

		_, err := evaluator.EvaluateAccreditations(ctx, realmName, userID, fieldsComparator, accreds)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mockAccreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return([]string{"ONE"}, nil)

		res, err := evaluator.EvaluateAccreditations(ctx, realmName, userID, fieldsComparator, accreds)
		assert.Nil(t, err)
		assert.Len(t, res, 3)
		for _, accreditation := range res {
			if strings.Contains(accreditation, `"type":"ONE"`) {
				assert.Contains(t, accreditation, `"revoked":true`)
			} else {
				assert.NotContains(t, accreditation, `"revoked":true`)
			}
		}
	})
}
