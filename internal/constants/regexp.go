package constants

// Regular expressions for parameters validation
const (
	regExpLen255 = `^.{1,255}$`
	regExpLen128 = `^.{1,128}$`

	RegExpID          = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
	RegExpName        = `^[a-zA-Z0-9-_]{1,128}$`
	RegExpDescription = regExpLen255
	RegExpBool        = `^([Tt][Rr][Uu][Ee])|([Ff][Aa][Ll][Ss][Ee])$`

	// Client
	RegExpClientID = `^[a-zA-Z0-9-_.]{1,255}$`

	// User
	RegExpUsername         = `^[a-zA-Z0-9-_.]{1,128}$`
	RegExpEmail            = `^.+\@.+\..+$`
	RegExpNameSpecialChars = `^([\wàáâäçèéêëìíîïñòóôöùúûüß][\wàáâäçèéêëìíîïñòóôöùúûüß \.'-]{0,49})$`
	RegExpFirstName        = regExpLen128
	RegExpLastName         = regExpLen128
	RegExpPhoneNumber      = `^\+[1-9]\d{1,14}$`
	RegExpLabel            = regExpLen255
	RegExpGender           = `^[MFU]$`
	RegExpBirthDate        = `^(\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))$`
	RegExpLocale           = `^[a-z]{2}$`
	RegExpCountryCode      = `^\w{2}$`
	RegExpIDDocumentNumber = `^([\w\d]+([\. -][\w\d]+)*){1,50}$`

	// Password
	RegExpPassword = regExpLen255

	// RealmCustomConfiguration/RealmAdminConfiguration
	RegExpRedirectURI = `^\w+:(\/?\/?)[^\s]+$`
	RegExpTheme       = RegExpName

	// RequiredAction
	RegExpRequiredAction = `^[a-zA-Z0-9-_]{1,255}$`

	// Others
	RegExpRealmName = `^[a-zA-Z0-9_-]{1,36}$`
	RegExpSearch    = regExpLen128
	RegExpLifespan  = `^[0-9]{1,10}$`
	RegExpGroupIds  = `^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})(,[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}){0,20}$`
	RegExpNumber    = `^\d+$`
)

var (
	// AllowedDocumentTypes are the valid document type for identification
	AllowedDocumentTypes = map[string]bool{"ID_CARD": true, "PASSPORT": true, "RESIDENCE_PERMIT": true}
)
