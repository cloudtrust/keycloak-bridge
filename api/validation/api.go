package apivalidation

import (
	"time"

	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// UserRepresentation struct
type UserRepresentation struct {
	UserID               *string    `json:"userId,omitempty"`
	Username             *string    `json:"username,omitempty"`
	Gender               *string    `json:"gender,omitempty"`
	FirstName            *string    `json:"firstName,omitempty"`
	LastName             *string    `json:"lastName,omitempty"`
	EmailAddress         *string    `json:"emailAddress,omitempty"`
	EmailAddressVerified *bool      `json:"emailAddressVerified,omitempty"`
	PhoneNumber          *string    `json:"phoneNumber,omitempty"`
	PhoneNumberVerified  *bool      `json:"phoneNumberVerified,omitempty"`
	BirthDate            *time.Time `json:"birthDate,omitempty"`
	BirthLocation        *string    `json:"birthLocation,omitempty"`
	IDDocumentType       *string    `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string    `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *time.Time `json:"idDocumentExpiration,omitempty"`
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
}

// Parameter references
const (
	prmUserID               = "user_id"
	prmUserGender           = "user_gender"
	prmUserFirstName        = "user_firstName"
	prmUserLastName         = "user_lastName"
	prmUserEmail            = "user_emailAddress"
	prmUserPhoneNumber      = "user_phoneNumber"
	prmUserBirthLocation    = "user_birthLocation"
	prmUserIDDocumentType   = "user_idDocType"
	prmUserIDDocumentNumber = "user_idDocNumber"

	prmCheckOperator  = "check_operator"
	prmCheckDatetime  = "check_datetime"
	prmCheckStatus    = "check_status"
	prmCheckType      = "check_type"
	prmCheckNature    = "check_nature"
	prmCheckProofType = "check_proof_type"

	RegExpRealmName     = constants.RegExpRealmName
	RegExpID            = constants.RegExpID
	regExpFirstName     = constants.RegExpNameSpecialChars
	regExpLastName      = constants.RegExpNameSpecialChars
	regExpEmail         = constants.RegExpEmail
	regExpBirthLocation = constants.RegExpNameSpecialChars
	// Multiple values with digits and letters separated by a single separator (space, dash, dot)
	regExpIDDocumentNumber = constants.RegExpIDDocumentNumber

	regExpAlphaNum255 = `[a-zA-Z0-9_-]{1,255}`
	regExpOperator    = regExpAlphaNum255
	regExpNature      = regExpAlphaNum255
	regExpProofType   = regExpAlphaNum255
)

var (
	allowedGender       = map[string]bool{"M": true, "F": true}
	allowedDocumentType = map[string]bool{"ID_CARD": true, "PASSPORT": true, "RESIDENCE_PERMIT": true}
	allowedCheckType    = map[string]bool{"IDENTITY_CHECK": true}
	allowedStatus       = map[string]bool{
		"SUCCESS":                   true,
		"SUCCESS_DATA_CHANGED":      true,
		"FRAUD_SUSPICION_CONFIRMED": true,
		"REVIEW_PENDING":            true,
		"FRAUD_SUSPICION_PENDING":   true,
	}
	successStatus = map[string]bool{
		"SUCCESS":              true,
		"SUCCESS_DATA_CHANGED": true,
	}
)

// ConvertToDBCheck creates a DBCheck
func (c *CheckRepresentation) ConvertToDBCheck() dto.DBCheck {
	var check = dto.DBCheck{}
	check.Operator = c.Operator
	datetime := *c.DateTime
	check.DateTime = &datetime
	check.Status = c.Status
	check.Type = c.Type
	check.Nature = c.Nature
	check.ProofType = c.ProofType
	check.ProofData = c.ProofData

	return check
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

	u.UserID = kcUser.ID
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
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserID, u.UserID, RegExpID, false).
		ValidateParameterIn(prmUserGender, u.Gender, allowedGender, false).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, false).
		ValidateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, false).
		ValidateParameterRegExp(prmUserEmail, u.EmailAddress, regExpEmail, false).
		ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, false).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, false).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, allowedDocumentType, false).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, false).
		Status()
}

// HasUpdateOfAccreditationDependantInformationDB checks user data contains an update of accreditation-dependant information
func (u *UserRepresentation) HasUpdateOfAccreditationDependantInformationDB(formerUserInfo dto.DBUser) bool {
	var expiry *string
	if u.IDDocumentExpiration != nil {
		var converted = u.IDDocumentExpiration.Format(constants.SupportedDateLayouts[0])
		expiry = &converted
	}
	return keycloakb.IsUpdated(u.BirthLocation, formerUserInfo.BirthLocation,
		u.IDDocumentType, formerUserInfo.IDDocumentType,
		u.IDDocumentNumber, formerUserInfo.IDDocumentNumber,
		expiry, formerUserInfo.IDDocumentExpiration)
}

// HasUpdateOfAccreditationDependantInformationKC checks user data contains an update of accreditation-dependant information
func (u *UserRepresentation) HasUpdateOfAccreditationDependantInformationKC(formerUserInfo *kc.UserRepresentation) bool {
	var birthDate *string
	if u.BirthDate != nil {
		var converted = u.BirthDate.Format(constants.SupportedDateLayouts[0])
		birthDate = &converted
	}
	return keycloakb.IsUpdated(u.FirstName, formerUserInfo.FirstName,
		u.LastName, formerUserInfo.LastName,
		u.Gender, formerUserInfo.GetAttributeString(constants.AttrbGender),
		birthDate, formerUserInfo.GetAttributeString(constants.AttrbBirthDate))
}

// Validate checks the validity of the given check
func (c *CheckRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserID, c.UserID, RegExpID, true).
		ValidateParameterRegExp(prmCheckOperator, c.Operator, regExpOperator, true).
		ValidateParameterNotNil(prmCheckDatetime, c.DateTime).
		ValidateParameterIn(prmCheckStatus, c.Status, allowedStatus, true).
		ValidateParameterIn(prmCheckType, c.Type, allowedCheckType, true).
		ValidateParameterRegExp(prmCheckNature, c.Nature, regExpNature, true).
		ValidateParameterRegExp(prmCheckProofType, c.ProofType, regExpProofType, true).
		Status()
}

// IsIdentificationSuccessful tells whether a check is success or not
func (c *CheckRepresentation) IsIdentificationSuccessful() bool {
	return c.Status != nil && successStatus[*c.Status]
}
