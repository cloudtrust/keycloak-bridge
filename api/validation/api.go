package apivalidation

import (
	"time"

	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
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

// CheckRepresentation struct
type CheckRepresentation struct {
	UserID    *string    `json:"userId,omitempty"`
	Operator  *string    `json:"operator,omitempty"`
	DateTime  *time.Time `json:"datetime,omitempty"`
	Status    *string    `json:"status,omitempty"`
	Type      *string    `json:"type,omitempty"`
	Nature    *string    `json:"nature,omitempty"`
	ProofData *[]byte    `json:"proofData,omitempty"`
	ProofType *string    `json:"proofType,omitempty"`
	TxnID     *string    `json:"txnId,omitempty"`
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

	prmCheckOperator  = "check_operator"
	prmCheckDatetime  = "check_datetime"
	prmCheckStatus    = "check_status"
	prmCheckType      = "check_type"
	prmCheckNature    = "check_nature"
	prmCheckProofType = "check_proof_type"
	prmCheckTxnID     = "check_txn_id"

	regExpAlphaNum255 = `[a-zA-Z0-9_-]{1,255}`
	regExpOperator    = regExpAlphaNum255
	regExpNature      = regExpAlphaNum255
	regExpProofType   = regExpAlphaNum255
	regExpStatus      = regExpAlphaNum255
)

var (
	allowedGender    = map[string]bool{"M": true, "F": true}
	allowedCheckType = map[string]bool{"IDENTITY_CHECK": true}
	successStatus    = map[string]bool{
		"SUCCESS":              true,
		"SUCCESS_DATA_CHANGED": true,
	}
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

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserID, u.ID, constants.RegExpID, false).
		ValidateParameterIn(prmUserGender, u.Gender, allowedGender, false).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, constants.RegExpFirstName, false).
		ValidateParameterRegExp(prmUserLastName, u.LastName, constants.RegExpLastName, false).
		ValidateParameterRegExp(prmUserEmail, u.Email, constants.RegExpEmail, false).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, false).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, constants.RegExpBirthLocation, false).
		ValidateParameterRegExp(prmUserNationality, u.Nationality, constants.RegExpCountryCode, false).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, constants.AllowedDocumentTypes, false).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, constants.RegExpIDDocumentNumber, false).
		ValidateParameterRegExp(prmUserIDDocumentCountry, u.IDDocumentCountry, constants.RegExpCountryCode, false).
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

// Validate checks the validity of the given check
func (c *CheckRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserID, c.UserID, constants.RegExpID, true).
		ValidateParameterRegExp(prmCheckOperator, c.Operator, regExpOperator, c.IsIdentificationSuccessful()).
		ValidateParameterNotNil(prmCheckDatetime, c.DateTime).
		ValidateParameterRegExp(prmCheckStatus, c.Status, regExpStatus, true).
		ValidateParameterIn(prmCheckType, c.Type, allowedCheckType, true).
		ValidateParameterRegExp(prmCheckNature, c.Nature, regExpNature, true).
		ValidateParameterRegExp(prmCheckProofType, c.ProofType, regExpProofType, true).
		ValidateParameterRegExp(prmCheckTxnID, c.TxnID, constants.RegExpTxnID, false).
		Status()
}

// IsIdentificationSuccessful tells whether a check is success or not
func (c *CheckRepresentation) IsIdentificationSuccessful() bool {
	return c.Status != nil && successStatus[*c.Status]
}

// IsIdentificationCanceled checks if the identification was canceled
func (c *CheckRepresentation) IsIdentificationCanceled() bool {
	return c.Status != nil && *c.Status == "CANCELED"
}

// IsIdentificationAborted checks if the identification was aborted
func (c *CheckRepresentation) IsIdentificationAborted() bool {
	return c.Status != nil && *c.Status == "ABORTED"
}
