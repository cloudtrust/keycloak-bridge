package apiregister

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	cerrors "github.com/cloudtrust/common-service/errors"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/nyaruka/phonenumbers"
)

// User representation
type User struct {
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

// Configuration representation
type Configuration struct {
	CancelURL *string `json:"cancelUrl,omitempty"`
}

// DBUser struct
type DBUser struct {
	UserID               *string `json:"-"`
	BirthLocation        *string `json:"birth_location,omitempty"`
	IDDocumentType       *string `json:"id_document_typ,omitempty"`
	IDDocumentNumber     *string `json:"id_document_num,omitempty"`
	IDDocumentExpiration *string `json:"id_document_exp,omitempty"`
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
func UserFromJSON(jsonRep string) (User, error) {
	var user User
	dec := json.NewDecoder(strings.NewReader(jsonRep))
	dec.DisallowUnknownFields()
	err := dec.Decode(&user)
	return user, err
}

// UserToJSON returns a json representation of a given User
func (u *User) UserToJSON() string {
	var bytes, _ = json.Marshal(u)
	return string(bytes)
}

// UpdateUserRepresentation converts a given User to a Keycloak UserRepresentation
func (u *User) UpdateUserRepresentation(kcUser *kc.UserRepresentation) {
	var (
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

	kcUser.Email = u.EmailAddress
	kcUser.EmailVerified = &bFalse
	kcUser.Enabled = &bFalse
	kcUser.FirstName = u.FirstName
	kcUser.LastName = u.LastName
	kcUser.Attributes = &attributes
}

// Validate checks the validity of the given User
func (u *User) Validate() error {
	var err = validateParameterIn(prmUserGender, u.Gender, allowedGender, true)
	if err != nil {
		return err
	}
	err = validateParameterRegExp(prmUserFirstName, u.FirstName, regExpFirstName, true)
	if err != nil {
		return err
	}
	err = validateParameterRegExp(prmUserLastName, u.LastName, regExpLastName, true)
	if err != nil {
		return err
	}
	err = validateParameterRegExp(prmUserEmail, u.EmailAddress, regExpEmail, true)
	if err != nil {
		return err
	}
	err = validateParameterPhoneNumber(prmUserPhoneNumber, u.PhoneNumber)
	if err != nil {
		return err
	}
	err = validateParameterDate(prmUserBirthDate, u.BirthDate, false)
	if err != nil {
		return err
	}
	err = validateParameterRegExp(prmUserBirthLocation, u.BirthLocation, regExpBirthLocation, false)
	if err != nil {
		return err
	}
	err = validateParameterIn(prmUserIDDocumentType, u.IDDocumentType, allowedDocumentType, false)
	if err != nil {
		return err
	}
	err = validateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, regExpIDDocumentNumber, false)
	if err != nil {
		return err
	}
	err = validateParameterDate(prmUserIDDocumentExpiration, u.IDDocumentExpiration, false)
	if err != nil {
		return err
	}
	return nil
}

func validateParameterIn(prmName string, value *string, allowedValues map[string]bool, mandatory bool) error {
	if value == nil {
		if mandatory {
			return cerrors.CreateMissingParameterError(prmName)
		}
	} else {
		if _, ok := allowedValues[*value]; !ok {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
		}
	}
	return nil
}

func validateParameterRegExp(prmName string, value *string, regExp string, mandatory bool) error {
	if value == nil {
		if mandatory {
			return cerrors.CreateMissingParameterError(prmName)
		}
	} else {
		res, _ := regexp.MatchString(regExp, strings.ToLower(*value))
		if !res {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
		}
	}
	return nil
}

func validateParameterPhoneNumber(prmName string, value *string) error {
	if value == nil {
		return cerrors.CreateMissingParameterError(prmName)
	}
	var metadata, err = phonenumbers.Parse(*value, "CH")
	if err != nil || !phonenumbers.IsPossibleNumber(metadata) {
		return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
	}
	return nil
}

func validateParameterDate(prmName string, value *string, mandatory bool) error {
	if value == nil {
		if mandatory {
			return cerrors.CreateMissingParameterError(prmName)
		}
	} else {
		var _, err = time.Parse(dateLayout, *value)
		if err != nil {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
		}
	}
	return nil
}
