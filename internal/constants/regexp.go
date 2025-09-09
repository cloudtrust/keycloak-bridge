package constants

// Regular expressions for parameters validation
const (
	regExpLen255OrEmpty = `^.{0,255}$`
	regExpLen255        = `^.{1,255}$`
	regExpLen128        = `^.{1,128}$`

	// Common regex
	RegExpID              = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
	RegExpFederatedUserID = regExpLen128
	RegExpName            = `^[a-zA-Z0-9-_]{1,128}$`
	RegExpDescription     = regExpLen255
	RegExpBool            = `^([Tt][Rr][Uu][Ee])|([Ff][Aa][Ll][Ss][Ee])$`

	// Client
	RegExpClientID = `^[a-zA-Z0-9-_.]{1,255}$`

	// User
	RegExpUsername            = `^[a-z0-9-_.]{1,128}$`
	RegExpFederatedUsername   = regExpLen128
	RegExpEmail               = `^.+\@.+\..+$`
	RegExpNameSpecialChars    = `^([\p{Lu}\p{Ll}][\p{Lu}\p{Ll} /\\\.',-]{0,49})$`
	RegExpNameSpecialChars128 = `^([\p{Lu}\p{Ll}][\p{Lu}\p{Ll} /\\\.',-]{0,127})$`
	RegExpPhoneNumber         = `^\+[1-9]\d{1,14}$`
	RegExpLabel               = regExpLen255
	RegExpGender              = `^[MFU]$`
	RegExpBirthDate           = `^(\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))$`
	RegExpLocale              = `^[a-z]{2}$`
	RegExpBusinessID          = regExpLen255

	// Password
	RegExpPassword        = regExpLen255
	RegExpPasswordOrEmpty = regExpLen255OrEmpty

	// RealmCustomConfiguration/RealmAdminConfiguration
	RegExpRedirectURI    = `^\w+:(\/?\/?)[^\s]+$`
	RegExpAllowedBackURL = `^((\w+:(\/?\/?)[^\s]+)|\*)$`
	RegExpTheme          = RegExpName

	// RequiredAction
	RegExpRequiredAction = `^[a-zA-Z0-9-_]{1,255}$`

	// Others
	RegExpRealmName       = `^[a-zA-Z0-9_-]{1,36}$`
	RegExpTargetRealmName = `^([a-zA-Z0-9_-]{1,36}|\*){1}$`
	RegExpTargetGroupID   = `^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}|\*){1}$`
	RegExpSearch          = regExpLen128
	RegExpLifespan        = `^[0-9]{1,10}$`
	RegExpGroupIds        = `^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})(,[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}){0,20}$`
	RegExpNumber          = `^\d+$`
	RegExpContainerID     = regExpLen255
	RegExpRoleDescription = regExpLen255OrEmpty

	RegExpCustomValue   = `^[A-Za-z\d_-]{0,50}$`
	RegExpAccreditation = `^[A-Za-z\d_-]{1,50}$`
	RegExpServiceType   = `^[\w_-]+$`
	RegExpTxnID         = regExpLen255

	RegExpColor	  = `^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`

	// Corporate Regex TO CLEAN WHEN WE WILL HAVE ATTRIBUTE MANAGEMENT
	regExpLen128OrEmpty      = `^.{0,128}$`
	RegExpCorporateFirstName = regExpLen128OrEmpty
	RegExpCorporateLastName  = regExpLen128

	// Identity provider
	RegExpAlias                     = RegExpRealmName
	RegExpDisplayName               = `^[a-zA-Z0-9 _-]{1,128}$`
	RegExpFirstBrokerLoginFlowAlias = `^[a-zA-Z0-9 _-]{1,128}$`
	RegExpPostBrokerLoginFlowAlias  = `^[a-zA-Z0-9 _-]{1,128}$`
	RegExpProviderID                = `^[a-z0-9\-]{1,36}$`
)

// Overridable user details regex and document types
var (
	// AllowedDocumentTypes are the valid document type for identification
	AllowedDocumentTypes = map[string]bool{"ID_CARD": true, "PASSPORT": true, "RESIDENCE_PERMIT": true}
)
