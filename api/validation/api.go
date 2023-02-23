package apivalidation

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/profile"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// AccreditationRepresentation struct
type AccreditationRepresentation struct {
	Name     *string `json:"name,omitempty"`
	Validity *string `json:"validity,omitempty"`
}

// UserRepresentation struct
type UserRepresentation struct {
	ID                   *string    `json:"id,omitempty"`
	Username             *string    `json:"username,omitempty"`
	Gender               *string    `json:"gender,omitempty"`
	FirstName            *string    `json:"firstName,omitempty"`
	LastName             *string    `json:"lastName,omitempty"`
	Email                *string    `json:"email,omitempty"`
	EmailVerified        *bool      `json:"emailVerified,omitempty"`
	PhoneNumber          *string    `json:"phoneNumber,omitempty"`
	PhoneNumberVerified  *bool      `json:"phoneNumberVerified,omitempty"`
	Locale               *string    `json:"locale,omitempty"`
	BirthDate            *time.Time `json:"birthDate,omitempty"`
	BirthLocation        *string    `json:"birthLocation,omitempty"`
	Nationality          *string    `json:"nationality,omitempty"`
	IDDocumentType       *string    `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string    `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *time.Time `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry    *string    `json:"idDocumentCountry,omitempty"`
}

// GroupRepresentation struct
type GroupRepresentation struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// Parameter references
const (
	prmAccreditationName     = "accred_name"
	prmAccreditationValidity = "accred_validity"

	prmUserID                = "user_id"
	prmUserGender            = "user_gender"
	prmUserFirstName         = "user_firstName"
	prmUserLastName          = "user_lastName"
	prmUserEmail             = "user_emailAddress"
	prmUserPhoneNumber       = "user_phoneNumber"
	prmUserBirthLocation     = "user_birthLocation"
	prmUserNationality       = "user_nationality"
	prmUserIDDocumentType    = "user_idDocType"
	prmUserIDDocumentNumber  = "user_idDocNumber"
	prmUserIDDocumentCountry = "user_idDocCountry"

	regExpAlphaNum255 = `[a-zA-Z0-9_-]{1,255}`
	regExpOperator    = regExpAlphaNum255
	regExpNature      = regExpAlphaNum255
	regExpProofType   = regExpAlphaNum255
	regExpStatus      = regExpAlphaNum255
)

// Validate validates an accreditation representation
func (a *AccreditationRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmAccreditationName, a.Name, regExpAlphaNum255, true).
		ValidateParameterLargeDuration(prmAccreditationValidity, a.Validity, true).
		Status()
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
		if phoneNumber := attributes.GetString(constants.AttrbPhoneNumber); phoneNumber == nil || *phoneNumber != *u.PhoneNumber {
			attributes.SetString(constants.AttrbPhoneNumber, *u.PhoneNumber)
			attributes.SetBool(constants.AttrbPhoneNumberVerified, false)
		}
	}
	attributes.SetTimeWhenNotNil(constants.AttrbBirthDate, u.BirthDate, constants.SupportedDateLayouts[0])
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, u.BirthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, u.Nationality)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, u.IDDocumentType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, u.IDDocumentNumber)
	attributes.SetTimeWhenNotNil(constants.AttrbIDDocumentExpiration, u.IDDocumentExpiration, constants.SupportedDateLayouts[0])
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, u.IDDocumentCountry)

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
func (u *UserRepresentation) ImportFromKeycloak(kcUser kc.UserRepresentation) {
	u.PhoneNumber = defaultIfNil(kcUser.GetAttributeString(constants.AttrbPhoneNumber), u.PhoneNumber)
	u.Locale = defaultIfNil(kcUser.GetAttributeString(constants.AttrbLocale), u.Locale)
	u.Gender = defaultIfNil(kcUser.GetAttributeString(constants.AttrbGender), u.Gender)
	u.BirthLocation = defaultIfNil(kcUser.GetAttributeString(constants.AttrbBirthLocation), u.BirthLocation)
	u.Nationality = defaultIfNil(kcUser.GetAttributeString(constants.AttrbNationality), u.Nationality)
	u.IDDocumentType = defaultIfNil(kcUser.GetAttributeString(constants.AttrbIDDocumentType), u.IDDocumentType)
	u.IDDocumentNumber = defaultIfNil(kcUser.GetAttributeString(constants.AttrbIDDocumentNumber), u.IDDocumentNumber)
	u.IDDocumentCountry = defaultIfNil(kcUser.GetAttributeString(constants.AttrbIDDocumentCountry), u.IDDocumentCountry)

	if kcUser.Attributes != nil {
		if value, err := kcUser.GetAttributeBool(constants.AttrbPhoneNumberVerified); err == nil && value != nil {
			u.PhoneNumberVerified = value
		}
		if value, err := kcUser.GetAttributeTime(constants.AttrbBirthDate, constants.SupportedDateLayouts); err == nil && value != nil {
			u.BirthDate = value
		}
		if value, err := kcUser.GetAttributeTime(constants.AttrbIDDocumentExpiration, constants.SupportedDateLayouts); err == nil && value != nil {
			u.IDDocumentExpiration = value
		}
	}

	u.ID = kcUser.ID
	u.Username = kcUser.Username
	u.FirstName = kcUser.FirstName
	u.LastName = kcUser.LastName
	u.Email = kcUser.Email
	u.EmailVerified = kcUser.EmailVerified
}

func defaultIfNil(value *string, defaultValue *string) *string {
	if value != nil {
		return value
	}
	return defaultValue
}

// Validators

// GetField is used to validate a user against a UserProfile
func (u *UserRepresentation) GetField(field string) interface{} {
	switch field {
	case fields.Username.Key():
		return profile.IfNotNil(u.Username)
	case fields.Email.Key():
		return profile.IfNotNil(u.Email)
	case fields.FirstName.Key():
		return profile.IfNotNil(u.FirstName)
	case fields.LastName.Key():
		return profile.IfNotNil(u.LastName)
	case fields.Gender.AttributeName():
		return profile.IfNotNil(u.Gender)
	case fields.PhoneNumber.AttributeName():
		return profile.IfNotNil(u.PhoneNumber)
	case fields.BirthDate.AttributeName():
		return profile.IfTimePtrNotNil(u.BirthDate)
	case fields.BirthLocation.AttributeName():
		return profile.IfNotNil(u.BirthLocation)
	case fields.Nationality.AttributeName():
		return profile.IfNotNil(u.Nationality)
	case fields.IDDocumentType.AttributeName():
		return profile.IfNotNil(u.IDDocumentType)
	case fields.IDDocumentNumber.AttributeName():
		return profile.IfNotNil(u.IDDocumentNumber)
	case fields.IDDocumentCountry.AttributeName():
		return profile.IfNotNil(u.IDDocumentCountry)
	case fields.IDDocumentExpiration.AttributeName():
		return profile.IfTimePtrNotNil(u.IDDocumentExpiration)
	case fields.Locale.AttributeName():
		return profile.IfNotNil(u.Locale)
	default:
		return nil
	}
}

// SetField is used to validate a user against a UserProfile
func (u *UserRepresentation) SetField(field string, value interface{}) {
	switch field {
	case fields.Username.Key():
		u.Username = cs.ToStringPtr(value)
		break
	case fields.Email.Key():
		u.Email = cs.ToStringPtr(value)
		break
	case fields.FirstName.Key():
		u.FirstName = cs.ToStringPtr(value)
		break
	case fields.LastName.Key():
		u.LastName = cs.ToStringPtr(value)
		break
	case fields.Gender.AttributeName():
		u.Gender = cs.ToStringPtr(value)
		break
	case fields.PhoneNumber.AttributeName():
		u.PhoneNumber = cs.ToStringPtr(value)
		break
	case fields.BirthDate.AttributeName():
		u.BirthDate = cs.ToTimePtr(value)
		break
	case fields.BirthLocation.AttributeName():
		u.BirthLocation = cs.ToStringPtr(value)
		break
	case fields.Nationality.AttributeName():
		u.Nationality = cs.ToStringPtr(value)
		break
	case fields.IDDocumentType.AttributeName():
		u.IDDocumentType = cs.ToStringPtr(value)
		break
	case fields.IDDocumentNumber.AttributeName():
		u.IDDocumentNumber = cs.ToStringPtr(value)
		break
	case fields.IDDocumentCountry.AttributeName():
		u.IDDocumentCountry = cs.ToStringPtr(value)
		break
	case fields.IDDocumentExpiration.AttributeName():
		u.IDDocumentExpiration = cs.ToTimePtr(value)
		break
	case fields.Locale.AttributeName():
		u.Locale = cs.ToStringPtr(value)
		break
	}
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate(ctx context.Context, upc profile.UserProfile, realm string) error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserID, u.ID, constants.RegExpID, false).
		ValidateParameterFunc(func() error {
			return profile.Validate(ctx, upc, realm, u, "validation", true)
		}).
		Status()
}

// UpdateFieldsComparatorWithKCFields update the field comparator with fields stored in KC
func (u *UserRepresentation) UpdateFieldsComparatorWithKCFields(fc fields.FieldsComparator, formerUserInfo *kc.UserRepresentation) fields.FieldsComparator {
	var birthDate *string
	if u.BirthDate != nil {
		var converted = u.BirthDate.Format(constants.SupportedDateLayouts[0])
		birthDate = &converted
	}
	var expiry *string
	if u.IDDocumentExpiration != nil {
		var converted = u.IDDocumentExpiration.Format(constants.SupportedDateLayouts[0])
		expiry = &converted
	}

	return fc.
		CompareValues(fields.FirstName, u.FirstName, formerUserInfo.FirstName).
		CompareValues(fields.LastName, u.LastName, formerUserInfo.LastName).
		CaseSensitive(false).
		CompareValueAndFunction(fields.Gender, u.Gender, formerUserInfo.GetFieldValues).
		CaseSensitive(true).
		CompareValueAndFunction(fields.BirthDate, birthDate, formerUserInfo.GetFieldValues).
		CompareValueAndFunction(fields.BirthLocation, u.BirthLocation, formerUserInfo.GetFieldValues).
		CompareValueAndFunction(fields.Nationality, u.Nationality, formerUserInfo.GetFieldValues).
		CompareValueAndFunction(fields.IDDocumentType, u.IDDocumentType, formerUserInfo.GetFieldValues).
		CompareValueAndFunction(fields.IDDocumentNumber, u.IDDocumentNumber, formerUserInfo.GetFieldValues).
		CompareValueAndFunction(fields.IDDocumentExpiration, expiry, formerUserInfo.GetFieldValues).
		CompareValueAndFunction(fields.IDDocumentCountry, u.IDDocumentCountry, formerUserInfo.GetFieldValues)
}
