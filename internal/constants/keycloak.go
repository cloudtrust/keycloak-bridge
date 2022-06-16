package constants

import (
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// Date layout management: first date layout is the one used to format dates in Keycloak.
// Following one are other supported format when parsing
var (
	SupportedDateLayouts = []string{"02.01.2006", "2006-01-02"}
)

// Attribute keys definition
const (
	AttrbAccreditations        = kc.AttributeKey("accreditations")
	AttrbBirthDate             = kc.AttributeKey("ENC_birthDate")
	AttrbBusinessID            = kc.AttributeKey("businessID")
	AttrbPendingChecks         = kc.AttributeKey("pendingChecks")
	AttrbGender                = kc.AttributeKey("ENC_gender")
	AttrbLabel                 = kc.AttributeKey("label")
	AttrbLocale                = kc.AttributeKey("locale")
	AttrbNameID                = kc.AttributeKey("saml.persistent.name.id.for.*")
	AttrbOnboardingCompleted   = kc.AttributeKey("onboardingCompleted")
	AttrbPhoneNumber           = kc.AttributeKey("phoneNumber")
	AttrbPhoneNumberVerified   = kc.AttributeKey("phoneNumberVerified")
	AttrbPhoneNumberToValidate = kc.AttributeKey("phoneNumberToValidate")
	AttrbEmailToValidate       = kc.AttributeKey("emailToValidate")
	AttrbSmsSent               = kc.AttributeKey("smsSent")
	AttrbSmsAttempts           = kc.AttributeKey("smsAttempts")
	AttrbSource                = kc.AttributeKey("src")
	AttrbTrustIDAuthToken      = kc.AttributeKey("trustIDAuthToken")
	AttrbTrustIDGroups         = kc.AttributeKey("trustIDGroups")
)
