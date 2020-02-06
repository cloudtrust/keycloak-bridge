package apikyc

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// ActionRepresentation struct
type ActionRepresentation struct {
	Name  *string `json:"name"`
	Scope *string `json:"scope"`
}

// UserRepresentation contains user details
type UserRepresentation struct {
	UserID               *string `json:"userId,omitempty"`
	Username             *string `json:"username,omitempty"`
	Gender               *string `json:"gender,omitempty"`
	FirstName            *string `json:"firstName,omitempty"`
	LastName             *string `json:"lastName,omitempty"`
	EmailAddress         *string `json:"emailAddress,omitempty"`
	EmailAddressVerified *bool   `json:"emailAddressVerified,omitempty"`
	PhoneNumber          *string `json:"phoneNumber,omitempty"`
	PhoneNumberVerified  *bool   `json:"phoneNumberVerified,omitempty"`
	BirthDate            *string `json:"birthDate,omitempty"`
	BirthLocation        *string `json:"birthLocation,omitempty"`
	IDDocumentType       *string `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string `json:"idDocumentExpiration,omitempty"`
	Comment              *string `json:"comment,omitempty"`
	Validation           *string `json:"validation,omitempty"`
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

	regExpNames         = `^([\wàáâäçèéêëìíîïñòóôöùúûüß]+([ '-][\wàáâäçèéêëìíîïñòóôöùúûüß]+)*){1,50}$`
	regExpFirstName     = regExpNames
	regExpLastName      = regExpNames
	regExpEmail         = `^.+\@.+\..+$`
	regExpBirthLocation = regExpNames
	// Multiple values with digits and letters separated by a single separator (space, dash)
	regExpIDDocumentNumber = `^([\w\d]+([ -][\w\d]+)*){1,50}$`

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

// ExportToKeycloak exports user details into a Keycloak UserRepresentation
func (u *UserRepresentation) ExportToKeycloak(kcUser *kc.UserRepresentation) {
	var bFalse = false
	var bTrue = true
	var attributes = make(map[string][]string)

	if kcUser.Attributes != nil {
		attributes = *kcUser.Attributes
	}

	if u.Gender != nil {
		attributes["gender"] = []string{*u.Gender}
	}
	if u.PhoneNumber != nil {
		if value, ok := attributes["phoneNumber"]; !ok || (len(value) > 0 && value[0] != *u.PhoneNumber) {
			attributes["phoneNumber"] = []string{*u.PhoneNumber}
			attributes["phoneNumberVerified"] = []string{"false"}
		}
	}
	if u.BirthDate != nil {
		attributes["birthDate"] = []string{*u.BirthDate}
	}

	if u.Username != nil {
		kcUser.Username = u.Username
	}
	if u.EmailAddress != nil && (kcUser.Email == nil || *kcUser.Email != *u.EmailAddress) {
		kcUser.Email = u.EmailAddress
		kcUser.EmailVerified = &bFalse
	}
	if u.FirstName != nil {
		kcUser.FirstName = u.FirstName
	}
	if u.LastName != nil {
		kcUser.LastName = u.LastName
	}
	kcUser.Attributes = &attributes
	kcUser.Enabled = &bTrue
}

// ImportFromKeycloak import details from Keycloak
func (u *UserRepresentation) ImportFromKeycloak(kcUser *kc.UserRepresentation) {
	var phoneNumber = u.PhoneNumber
	var phoneNumberVerified = u.PhoneNumberVerified
	var gender = u.Gender
	var birthdate = u.BirthDate

	if kcUser.Attributes != nil {
		var m = *kcUser.Attributes
		if value, ok := m["phoneNumber"]; ok && len(value) > 0 {
			phoneNumber = &value[0]
		}
		if value, ok := m["phoneNumberVerified"]; ok && len(value) > 0 {
			if verified, err := strconv.ParseBool(value[0]); err == nil {
				phoneNumberVerified = &verified
			}
		}
		if value, ok := m["gender"]; ok && len(value) > 0 {
			gender = &value[0]
		}
		if value, ok := m["birthDate"]; ok && len(value) > 0 {
			birthdate = &value[0]
		}
	}

	u.UserID = kcUser.Id
	u.Username = kcUser.Username
	u.Gender = gender
	u.FirstName = kcUser.FirstName
	u.LastName = kcUser.LastName
	u.EmailAddress = kcUser.Email
	u.EmailAddressVerified = kcUser.EmailVerified
	u.PhoneNumber = phoneNumber
	u.PhoneNumberVerified = phoneNumberVerified
	u.BirthDate = birthdate
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate() error {
	return keycloakb.NewParameterValidator().
		ValidateParameterIn(prmUserGender, u.Gender, allowedGender, true).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, true).
		ValidateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, true).
		ValidateParameterRegExp(prmUserEmail, u.EmailAddress, regExpEmail, true).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber).
		ValidateParameterDate(prmUserBirthDate, u.BirthDate, dateLayout, true).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, true).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, allowedDocumentType, true).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, true).
		ValidateParameterDate(prmUserIDDocumentExpiration, u.IDDocumentExpiration, dateLayout, true).
		Status()
}
