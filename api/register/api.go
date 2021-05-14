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
	BusinessID           *string `json:"businessId,omitempty"`
}

// ConfigurationRepresentation representation
type ConfigurationRepresentation struct {
	RedirectCancelledRegistrationURL *string   `json:"redirect_cancelled_registration_url,omitempty"`
	Mode                             *string   `json:"mode,omitempty"`
	Theme                            *string   `json:"theme,omitempty"`
	SupportedLocales                 *[]string `json:"supportedLocales,omitempty"`
	SelfRegisterEnabled              *bool     `json:"selfRegisterEnabled,omitempty"`
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
	prmUserBusinessID           = "user_businessId"
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
	attributes.SetStringWhenNotNil(constants.AttrbBusinessID, u.BusinessID)

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
		ValidateParameterRegExp(prmUserGender, u.Gender, constants.RegExpGender, allFieldsMandatory).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, constants.RegExpFirstName, true).
		ValidateParameterRegExp(prmUserLastName, u.LastName, constants.RegExpLastName, true).
		ValidateParameterRegExp(prmUserEmail, u.Email, constants.RegExpEmail, true).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, allFieldsMandatory).
		ValidateParameterDateMultipleLayout(prmUserBirthDate, u.BirthDate, constants.SupportedDateLayouts, allFieldsMandatory).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, constants.RegExpBirthLocation, allFieldsMandatory).
		ValidateParameterRegExp(prmUserNationality, u.Nationality, constants.RegExpCountryCode, allFieldsMandatory).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, constants.AllowedDocumentTypes, allFieldsMandatory).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, constants.RegExpIDDocumentNumber, allFieldsMandatory).
		ValidateParameterLength(prmUserIDDocumentNumber, u.IDDocumentNumber, 1, 50, allFieldsMandatory).
		ValidateParameterDateMultipleLayout(prmUserIDDocumentExpiration, u.IDDocumentExpiration, constants.SupportedDateLayouts, allFieldsMandatory).
		ValidateParameterRegExp(prmUserIDDocumentCountry, u.IDDocumentCountry, constants.RegExpCountryCode, allFieldsMandatory).
		ValidateParameterRegExp(prmUserLocale, u.Locale, constants.RegExpLocale, true).
		ValidateParameterRegExp(prmUserBusinessID, u.BusinessID, constants.RegExpBusinessID, false).
		Status()
}
