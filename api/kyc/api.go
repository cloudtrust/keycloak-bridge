package apikyc

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
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
	ID                   *string                        `json:"id,omitempty"`
	Username             *string                        `json:"username,omitempty"`
	Gender               *string                        `json:"gender,omitempty"`
	FirstName            *string                        `json:"firstName,omitempty"`
	LastName             *string                        `json:"lastName,omitempty"`
	Email                *string                        `json:"email,omitempty"`
	EmailVerified        *bool                          `json:"emailVerified,omitempty"`
	PhoneNumber          *string                        `json:"phoneNumber,omitempty"`
	PhoneNumberVerified  *bool                          `json:"phoneNumberVerified,omitempty"`
	BirthDate            *string                        `json:"birthDate,omitempty"`
	BirthLocation        *string                        `json:"birthLocation,omitempty"`
	IDDocumentType       *string                        `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string                        `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string                        `json:"idDocumentExpiration,omitempty"`
	Comment              *string                        `json:"comment,omitempty"`
	Accreditations       *[]AccreditationRepresentation `json:"accreditations,omitempty"`
}

// AccreditationRepresentation is a representation of accreditations
type AccreditationRepresentation struct {
	Type       *string `json:"type"`
	ExpiryDate *string `json:"expiryDate"`
	Expired    *bool   `json:"expired,omitempty"`
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

	regExpNames            = `^([\wàáâäçèéêëìíîïñòóôöùúûüß]+([ '-][\wàáâäçèéêëìíîïñòóôöùúûüß]+)*){1,50}$`
	regExpFirstName        = regExpNames
	regExpLastName         = regExpNames
	regExpEmail            = `^.+\@.+\..+$`
	regExpBirthLocation    = regExpNames
	regExpIDDocumentNumber = constants.RegExpIDDocumentNumber
	regExpGender           = constants.RegExpGender

	dateLayout = "02.01.2006"
)

var (
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
	var attributes = make(kc.Attributes)

	if kcUser.Attributes != nil {
		attributes = *kcUser.Attributes
	}

	attributes.SetStringWhenNotNil(constants.AttrbGender, u.Gender)
	if u.PhoneNumber != nil {
		if value := attributes.GetString(constants.AttrbPhoneNumber); value == nil || *value != *u.PhoneNumber {
			attributes.SetString(constants.AttrbPhoneNumber, *u.PhoneNumber)
			attributes.SetBool(constants.AttrbPhoneNumberVerified, false)
		}
	}
	attributes.SetDateWhenNotNil(constants.AttrbBirthDate, u.BirthDate, constants.SupportedDateLayouts)

	if u.Username != nil {
		kcUser.Username = u.Username
	}
	if u.Email != nil && (kcUser.Email == nil || *kcUser.Email != *u.Email) {
		kcUser.Email = u.Email
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
func (u *UserRepresentation) ImportFromKeycloak(ctx context.Context, kcUser *kc.UserRepresentation, logger keycloakb.Logger) {
	var phoneNumber = u.PhoneNumber
	var phoneNumberVerified = u.PhoneNumberVerified
	var gender = u.Gender
	var birthdate = u.BirthDate
	var accreditations = u.Accreditations

	if value := kcUser.GetAttributeString(constants.AttrbPhoneNumber); value != nil {
		phoneNumber = value
	}
	if value, err := kcUser.GetAttributeBool(constants.AttrbPhoneNumberVerified); err == nil && value != nil {
		phoneNumberVerified = value
	}
	if value := kcUser.GetAttributeString(constants.AttrbGender); value != nil {
		gender = value
	}
	if value := kcUser.GetAttributeDate(constants.AttrbBirthDate, constants.SupportedDateLayouts); value != nil {
		birthdate = value
	}
	if values := kcUser.GetAttribute(constants.AttrbAccreditations); len(values) > 0 {
		var accreds []AccreditationRepresentation
		for _, accredJSON := range values {
			var accred AccreditationRepresentation
			if json.Unmarshal([]byte(accredJSON), &accred) == nil {
				accred.Expired = keycloakb.IsDateInThePast(accred.ExpiryDate)
				accreds = append(accreds, accred)
			} else {
				logger.Warn(ctx, "msg", "Can't unmarshall JSON", "json", accredJSON)
			}
		}
		accreditations = &accreds
	}

	u.ID = kcUser.ID
	u.Username = kcUser.Username
	u.Gender = gender
	u.FirstName = kcUser.FirstName
	u.LastName = kcUser.LastName
	u.Email = kcUser.Email
	u.EmailVerified = kcUser.EmailVerified
	u.PhoneNumber = phoneNumber
	u.PhoneNumberVerified = phoneNumberVerified
	u.BirthDate = birthdate
	u.Accreditations = accreditations
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserGender, u.Gender, regExpGender, true).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, true).
		ValidateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, true).
		ValidateParameterRegExp(prmUserEmail, u.Email, regExpEmail, true).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, true).
		ValidateParameterDate(prmUserBirthDate, u.BirthDate, dateLayout, true).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, true).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, allowedDocumentType, true).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, true).
		ValidateParameterDate(prmUserIDDocumentExpiration, u.IDDocumentExpiration, dateLayout, true).
		Status()
}
