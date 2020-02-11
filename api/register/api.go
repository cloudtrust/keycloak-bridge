package apiregister

import (
	"encoding/json"
	"strings"

	"github.com/cloudtrust/common-service/validation"
	kc "github.com/cloudtrust/keycloak-client"
)

// ActionRepresentation struct
type ActionRepresentation struct {
	Name  *string `json:"name"`
	Scope *string `json:"scope"`
}

// UserRepresentation representation
type UserRepresentation struct {
	Username             *string `json:"username,omitempty"`
	Gender               *string `json:"gender,omitempty"`
	FirstName            *string `json:"firstName,omitempty"`
	LastName             *string `json:"lastName,omitempty"`
	EmailAddress         *string `json:"emailAddress,omitempty"`
	PhoneNumber          *string `json:"phoneNumber,omitempty"`
	BirthDate            *string `json:"birthDate,omitempty"`
	BirthLocation        *string `json:"birthLocation,omitempty"`
	IDDocumentType       *string `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string `json:"idDocumentExpiration,omitempty"`
	Locale               *string `json:"locale,omitempty"`
}

// ConfigurationRepresentation representation
type ConfigurationRepresentation struct {
	RedirectCancelledRegistrationURL *string `json:"redirect_cancelled_registration_url,omitempty"`
}

// Parameter references
const (
	prmUserGender               = "user_gender"
	prmUserFirstName            = "user_firstName"
	prmUserLastName             = "user_lastName"
	prmUserEmail                = "user_emailAddress"
	prmUserPhoneNumber          = "user_phoneNumber"
	prmUserBirthDate            = "user_birthDate"
	prmUserBirthLocation        = "user_birthLocation"
	prmUserIDDocumentType       = "user_idDocType"
	prmUserIDDocumentNumber     = "user_idDocNumber"
	prmUserIDDocumentExpiration = "user_idDocExpiration"
	prmUserLocale               = "user_locale"

	regExpNames         = `^([\wàáâäçèéêëìíîïñòóôöùúûüß]+([ '-][\wàáâäçèéêëìíîïñòóôöùúûüß]+)*){1,50}$`
	regExpFirstName     = regExpNames
	regExpLastName      = regExpNames
	regExpEmail         = `^.+\@.+\..+$`
	regExpBirthLocation = regExpNames
	// Multiple values with digits and letters separated by a single separator (space, dash)
	regExpIDDocumentNumber = `^([\w\d]+([ -][\w\d]+)*){1,50}$`
	regExpLocale           = `^\w{2}(-\w{2})?$`

	dateLayout = "02.01.2006"
)

var (
	allowedGender       = map[string]bool{"M": true, "F": true}
	allowedDocumentType = map[string]bool{"ID_CARD": true, "PASSPORT": true, "RESIDENCE_PERMIT": true}
)

// UserFromJSON creates a User using its json representation
func UserFromJSON(jsonRep string) (UserRepresentation, error) {
	var user UserRepresentation
	dec := json.NewDecoder(strings.NewReader(jsonRep))
	dec.DisallowUnknownFields()
	err := dec.Decode(&user)
	return user, err
}

// UserToJSON returns a json representation of a given User
func (u *UserRepresentation) UserToJSON() string {
	var bytes, _ = json.Marshal(u)
	return string(bytes)
}

// ConvertToKeycloak converts a given User to a Keycloak UserRepresentation
func (u *UserRepresentation) ConvertToKeycloak() kc.UserRepresentation {
	var (
		bTrue      = true
		bFalse     = false
		attributes = make(map[string][]string)
	)

	if u.Gender != nil {
		attributes["gender"] = []string{*u.Gender}
	}
	if u.PhoneNumber != nil {
		attributes["phoneNumber"] = []string{*u.PhoneNumber}
		attributes["phoneNumberVerified"] = []string{"false"}
	}
	if u.BirthDate != nil {
		attributes["birthDate"] = []string{*u.BirthDate}
	}
	if u.Locale != nil {
		attributes["locale"] = []string{*u.Locale}
	}

	return kc.UserRepresentation{
		Username:      u.Username,
		Email:         u.EmailAddress,
		EmailVerified: &bFalse,
		Enabled:       &bTrue,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Attributes:    &attributes,
	}
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterIn(prmUserGender, u.Gender, allowedGender, true).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, true).
		ValidateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, true).
		ValidateParameterRegExp(prmUserEmail, u.EmailAddress, regExpEmail, true).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, true).
		ValidateParameterDate(prmUserBirthDate, u.BirthDate, dateLayout, true).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, true).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, allowedDocumentType, true).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, true).
		ValidateParameterDate(prmUserIDDocumentExpiration, u.IDDocumentExpiration, dateLayout, true).
		ValidateParameterRegExp(prmUserLocale, u.Locale, regExpLocale, true).
		Status()
}
