package apiregister

import (
	"encoding/json"
	"strings"

	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
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
	Email                *string `json:"email,omitempty"`
	PhoneNumber          *string `json:"phoneNumber,omitempty"`
	BirthDate            *string `json:"birthDate,omitempty"`
	BirthLocation        *string `json:"birthLocation,omitempty"`
	Nationality          *string `json:"nationality,omitempty"`
	IDDocumentType       *string `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry    *string `json:"idDocumentCountry,omitempty"`
	Locale               *string `json:"locale,omitempty"`
}

// ConfigurationRepresentation representation
type ConfigurationRepresentation struct {
	RedirectCancelledRegistrationURL *string `json:"redirect_cancelled_registration_url,omitempty"`
	Mode                             *string `json:"mode,omitempty"`
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
	prmUserNationality          = "user_nationality"
	prmUserIDDocumentType       = "user_idDocType"
	prmUserIDDocumentNumber     = "user_idDocNumber"
	prmUserIDDocumentExpiration = "user_idDocExpiration"
	prmUserIDDocumentCountry    = "user_idDocCountry"
	prmUserLocale               = "user_locale"

	regExpGender            = constants.RegExpGender
	regExpFirstName         = constants.RegExpNameSpecialChars
	regExpLastName          = constants.RegExpNameSpecialChars
	regExpEmail             = `^.+\@.+\..+$`
	regExpBirthLocation     = constants.RegExpNameSpecialChars
	regExpNationality       = constants.RegExpCountryCode
	regExpIDDocumentNumber  = constants.RegExpIDDocumentNumber
	regExpIDDocumentCountry = constants.RegExpCountryCode
	regExpLocale            = `^\w{2}(-\w{2})?$`
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
		attributes = make(kc.Attributes)
	)

	attributes.SetStringWhenNotNil(constants.AttrbGender, u.Gender)
	if u.PhoneNumber != nil {
		attributes.SetString(constants.AttrbPhoneNumber, *u.PhoneNumber)
		attributes.SetBool(constants.AttrbPhoneNumberVerified, false)
	}
	attributes.SetDateWhenNotNil(constants.AttrbBirthDate, u.BirthDate, constants.SupportedDateLayouts)
	attributes.SetStringWhenNotNil(constants.AttrbLocale, u.Locale)

	return kc.UserRepresentation{
		Username:      u.Username,
		Email:         u.Email,
		EmailVerified: &bFalse,
		Enabled:       &bTrue,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Attributes:    &attributes,
	}
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate(allFieldsMandatory bool) error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserGender, u.Gender, regExpGender, allFieldsMandatory).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, true).
		ValidateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, true).
		ValidateParameterRegExp(prmUserEmail, u.Email, regExpEmail, true).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, allFieldsMandatory).
		ValidateParameterDateMultipleLayout(prmUserBirthDate, u.BirthDate, constants.SupportedDateLayouts, allFieldsMandatory).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, allFieldsMandatory).
		ValidateParameterRegExp(prmUserNationality, u.Nationality, regExpNationality, allFieldsMandatory).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, constants.AllowedDocumentTypes, allFieldsMandatory).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, allFieldsMandatory).
		ValidateParameterLength(prmUserIDDocumentNumber, u.IDDocumentNumber, 1, 50, allFieldsMandatory).
		ValidateParameterDateMultipleLayout(prmUserIDDocumentExpiration, u.IDDocumentExpiration, constants.SupportedDateLayouts, allFieldsMandatory).
		ValidateParameterRegExp(prmUserIDDocumentCountry, u.IDDocumentCountry, regExpIDDocumentCountry, allFieldsMandatory).
		ValidateParameterRegExp(prmUserLocale, u.Locale, regExpLocale, true).
		Status()
}
