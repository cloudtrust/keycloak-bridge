package validation

import "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"

// UserRepresentation struct
type UserRepresentation struct {
	UserID               *string `json:"userId,omitempty"`
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
}

// CheckRepresentation struct
type CheckRepresentation struct {
	UserID    *string `json:"userId,omitempty"`
	Operator  *string `json:"operator,omitempty"`
	DateTime  *int64  `json:"datetime,omitempty"`
	Status    *string `json:"status,omitempty"`
	Type      *string `json:"type,omitempty"`
	Nature    *string `json:"nature,omitempty"`
	ProofData *[]byte `json:"proofData,omitempty"`
	ProofType *string `json:"proofType,omitempty"`
}

// Parameter references
const (
	prmUserID                   = "user_id"
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

	prmCheckOperator  = "check_operator"
	prmCheckDatetime  = "check_datetime"
	prmCheckStatus    = "check_status"
	prmCheckType      = "check_type"
	prmCheckNature    = "check_nature"
	prmCheckProofType = "check_proof_type"

	regExpID            = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
	regExpNames         = `^([\wàáâäçèéêëìíîïñòóôöùúûüß]+([ '-][\wàáâäçèéêëìíîïñòóôöùúûüß]+)*){1,50}$`
	regExpFirstName     = regExpNames
	regExpLastName      = regExpNames
	regExpEmail         = `^.+\@.+\..+$`
	regExpBirthLocation = regExpNames
	// Multiple values with digits and letters separated by a single separator (space, dash)
	regExpIDDocumentNumber = `^([\w\d]+([ -][\w\d]+)*){1,50}$`

	regExpOperator  = `[a-zA-Z0-9_-]{1,255}`
	regExpNature    = `[a-zA-Z0-9_-]{1,255}`
	regExpProofType = `[a-zA-Z0-9_-]{1,255}`

	dateLayout = "02.01.2006"
)

var (
	allowedGender       = map[string]bool{"M": true, "F": true}
	allowedDocumentType = map[string]bool{"ID_CARD": true, "PASSPORT": true, "RESIDENCE_PERMIT": true}
	allowedCheckType    = map[string]bool{"IDENTITY": true}
	allowedStatus       = map[string]bool{
		"SUCCESS":                   true,
		"SUCCESS_DATA_CHANGED":      true,
		"FRAUD_SUSPICION_CONFIRMED": true,
		"REVIEW_PENDING":            true,
		"FRAUD_SUSPICION_PENDING":   true,
	}
)

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate() error {
	var err = keycloakb.ValidateParameterRegExp(prmUserID, u.UserID, regExpID, false)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterIn(prmUserGender, u.Gender, allowedGender, false)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterRegExp(prmUserEmail, u.EmailAddress, regExpEmail, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterDate(prmUserBirthDate, u.BirthDate, dateLayout, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, allowedDocumentType, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, false)
	if err != nil {
		return err
	}
	err = keycloakb.ValidateParameterDate(prmUserIDDocumentExpiration, u.IDDocumentExpiration, dateLayout, false)
	if err != nil {
		return err
	}
	return nil
}

// Validate checks the validity of the given check
func (c *CheckRepresentation) Validate() error {
	var err = keycloakb.ValidateParameterRegExp(prmUserID, c.UserID, regExpID, true)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterRegExp(prmCheckOperator, c.Operator, regExpOperator, true)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterTimestamp(prmCheckDatetime, c.DateTime, true)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterIn(prmCheckStatus, c.Status, allowedStatus, true)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterIn(prmCheckType, c.Type, allowedCheckType, true)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterRegExp(prmCheckNature, c.Nature, regExpNature, true)
	if err != nil {
		return err
	}

	err = keycloakb.ValidateParameterRegExp(prmCheckProofType, c.ProofType, regExpProofType, true)
	if err != nil {
		return err
	}

	return nil
}
