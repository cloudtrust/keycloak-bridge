package constants

import (
	kc "github.com/cloudtrust/keycloak-client"
)

// Date layout management: first date layout is the one used to format dates in Keycloak.
// Following one are other supported format when parsing
var (
	SupportedDateLayouts = []string{"02.01.2006", "2006-01-02"}
)

// Attribute keys definition
const (
	AttrbAccreditations      = kc.AttributeKey("accreditations")
	AttrbBirthDate           = kc.AttributeKey("ENC_birthDate")
	AttrbGender              = kc.AttributeKey("ENC_gender")
	AttrbLabel               = kc.AttributeKey("label")
	AttrbLocale              = kc.AttributeKey("locale")
	AttrbPhoneNumber         = kc.AttributeKey("phoneNumber")
	AttrbPhoneNumberVerified = kc.AttributeKey("phoneNumberVerified")
	AttrbSmsSent             = kc.AttributeKey("smsSent")
	AttrbSmsAttempts         = kc.AttributeKey("smsAttempts")
	AttrbTrustIDAuthToken    = kc.AttributeKey("trustIDAuthToken")
	AttrbTrustIDGroups       = kc.AttributeKey("trustIDGroups")
)
