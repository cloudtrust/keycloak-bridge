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
	AttrbBirthDate           = kc.AttributeKey("birthDate")
	AttrbGender              = kc.AttributeKey("gender")
	AttrbLabel               = kc.AttributeKey("label")
	AttrbLocale              = kc.AttributeKey("locale")
	AttrbPhoneNumber         = kc.AttributeKey("phoneNumber")
	AttrbPhoneNumberVerified = kc.AttributeKey("phoneNumberVerified")
	AttrbSmsSent             = kc.AttributeKey("smsSent")
	AttrbTrustIDGroups       = kc.AttributeKey("trustIDGroups")
)
