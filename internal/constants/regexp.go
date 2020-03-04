package constants

// Regular expressions for parameters validation
const (
	RegExpID          = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
	RegExpName        = `^[a-zA-Z0-9-_]{1,128}$`
	RegExpDescription = `^.{1,255}$`

	// Client
	RegExpClientID = `^[a-zA-Z0-9-_.]{1,255}$`

	// User
	RegExpUsername         = `^[a-zA-Z0-9-_.]{1,128}$`
	RegExpEmail            = `^.+\@.+\..+$`
	RegExpNameSpecialChars = `^([\wàáâäçèéêëìíîïñòóôöùúûüß]+([ '-][\wàáâäçèéêëìíîïñòóôöùúûüß]+)*){1,50}$`
	RegExpFirstName        = `^.{1,128}$`
	RegExpLastName         = `^.{1,128}$`
	RegExpPhoneNumber      = `^\+[1-9]\d{1,14}$`
	RegExpLabel            = `^.{1,255}$`
	RegExpGender           = `^[MF]$`
	RegExpBirthDate        = `^(\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))$`
	RegExpLocale           = `^[a-z]{2}$`

	// Password
	RegExpPassword = `^.{1,255}$`

	// RealmCustomConfiguration
	RegExpRedirectURI = `^\w+:(\/?\/?)[^\s]+$`

	// RequiredAction
	RegExpRequiredAction = `^[a-zA-Z0-9-_]{1,255}$`

	// Others
	RegExpRealmName = `^[a-zA-Z0-9_-]{1,36}$`
	RegExpSearch    = `^.{1,128}$`
	RegExpLifespan  = `^[0-9]{1,10}$`
	RegExpGroupIds  = `^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})(,[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}){0,20}$`
	RegExpNumber    = `^\d+$`
)
