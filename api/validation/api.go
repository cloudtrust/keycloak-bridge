package apivalidation

import (
	"time"

	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
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
	var phoneNumber = u.PhoneNumber
	var phoneNumberVerified = u.PhoneNumberVerified
	var gender = u.Gender
	var birthdate = u.BirthDate

	if kcUser.Attributes != nil {
		if pn := kcUser.GetAttributeString(constants.AttrbPhoneNumber); pn != nil {
			phoneNumber = pn
		}
		if value, err := kcUser.GetAttributeBool(constants.AttrbPhoneNumberVerified); err == nil && value != nil {
			phoneNumberVerified = value
		}
		if value := kcUser.GetAttributeString(constants.AttrbGender); value != nil {
			gender = value
		}
		if value, err := kcUser.Attributes.GetTime(constants.AttrbBirthDate, constants.SupportedDateLayouts); err == nil && value != nil {
			birthdate = value
		}
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

// UpdateFieldsComparatorWithDBFields update the field comparator with fields stored in DB
func (u *UserRepresentation) UpdateFieldsComparatorWithDBFields(fc fields.FieldsComparator, formerUserInfo dto.DBUser) fields.FieldsComparator {
	var expiry *string
	if u.IDDocumentExpiration != nil {
		var converted = u.IDDocumentExpiration.Format(constants.SupportedDateLayouts[0])
		expiry = &converted
	}

	return fc.
		CompareValues(fields.BirthLocation, u.BirthLocation, formerUserInfo.BirthLocation).
		CompareValues(fields.Nationality, u.Nationality, formerUserInfo.Nationality).
		CompareValues(fields.IDDocumentType, u.IDDocumentType, formerUserInfo.IDDocumentType).
		CompareValues(fields.IDDocumentNumber, u.IDDocumentNumber, formerUserInfo.IDDocumentNumber).
		CompareValues(fields.IDDocumentExpiration, expiry, formerUserInfo.IDDocumentExpiration).
		CompareValues(fields.IDDocumentCountry, u.IDDocumentCountry, formerUserInfo.IDDocumentCountry)
}

// UpdateFieldsComparatorWithKCFields update the field comparator with fields stored in KC
func (u *UserRepresentation) UpdateFieldsComparatorWithKCFields(fc fields.FieldsComparator, formerUserInfo *kc.UserRepresentation) fields.FieldsComparator {
	var birthDate *string
	if u.BirthDate != nil {
		var converted = u.BirthDate.Format(constants.SupportedDateLayouts[0])
		birthDate = &converted
	}

	return fc.
		CompareValues(fields.FirstName, u.FirstName, formerUserInfo.FirstName).
		CompareValues(fields.LastName, u.LastName, formerUserInfo.LastName).
		CaseSensitive(false).
		CompareValueAndFunction(fields.Gender, u.Gender, formerUserInfo.GetFieldValues).
		CaseSensitive(true).
		CompareValueAndFunction(fields.BirthDate, birthDate, formerUserInfo.GetFieldValues)
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
