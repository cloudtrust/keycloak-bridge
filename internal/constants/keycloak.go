package constants

import (
	"github.com/cloudtrust/common-service/v2/fields"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// Date layout management: first date layout is the one used to format dates in Keycloak.
// Following one are other supported format when parsing
var (
	SupportedDateLayouts = []string{"02.01.2006", "2006-01-02"}
)

// Attribute keys definition
var (
	AttrbAccreditations        = kc.AttributeKey(fields.Accreditations.AttributeName())
	AttrbBirthDate             = kc.AttributeKey(fields.BirthDate.AttributeName())
	AttrbBusinessID            = kc.AttributeKey(fields.BusinessID.AttributeName())
	AttrbPendingChecks         = kc.AttributeKey(fields.PendingChecks.AttributeName())
	AttrbGender                = kc.AttributeKey(fields.Gender.AttributeName())
	AttrbLabel                 = kc.AttributeKey(fields.Label.AttributeName())
	AttrbLocale                = kc.AttributeKey(fields.Locale.AttributeName())
	AttrbNameID                = kc.AttributeKey(fields.NameID.AttributeName())
	AttrbOnboardingCompleted   = kc.AttributeKey(fields.OnboardingCompleted.AttributeName())
	AttrbPhoneNumber           = kc.AttributeKey(fields.PhoneNumber.AttributeName())
	AttrbPhoneNumberVerified   = kc.AttributeKey(fields.PhoneNumberVerified.AttributeName())
	AttrbPhoneNumberToValidate = kc.AttributeKey(fields.PhoneNumberToValidate.AttributeName())
	AttrbEmailToValidate       = kc.AttributeKey(fields.EmailToValidate.AttributeName())
	AttrbSmsSent               = kc.AttributeKey(fields.SmsSent.AttributeName())
	AttrbSmsAttempts           = kc.AttributeKey(fields.SmsAttempts.AttributeName())
	AttrbSource                = kc.AttributeKey(fields.Source.AttributeName())
	AttrbTrustIDAuthToken      = kc.AttributeKey(fields.TrustIDAuthToken.AttributeName())
	AttrbTrustIDGroups         = kc.AttributeKey(fields.TrustIDGroups.AttributeName())
	AttrbBirthLocation         = kc.AttributeKey(fields.BirthLocation.AttributeName())
	AttrbNationality           = kc.AttributeKey(fields.Nationality.AttributeName())
	AttrbIDDocumentType        = kc.AttributeKey(fields.IDDocumentType.AttributeName())
	AttrbIDDocumentNumber      = kc.AttributeKey(fields.IDDocumentNumber.AttributeName())
	AttrbIDDocumentExpiration  = kc.AttributeKey(fields.IDDocumentExpiration.AttributeName())
	AttrbIDDocumentCountry     = kc.AttributeKey(fields.IDDocumentCountry.AttributeName())
)
