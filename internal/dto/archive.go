package dto

import (
	"encoding/json"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// ArchiveUserRepresentation struct
type ArchiveUserRepresentation struct {
	ID                   *string                              `json:"-"`
	Username             *string                              `json:"username,omitempty"`
	Gender               *string                              `json:"gender,omitempty"`
	FirstName            *string                              `json:"firstName,omitempty"`
	LastName             *string                              `json:"lastName,omitempty"`
	Email                *string                              `json:"email,omitempty"`
	EmailVerified        *bool                                `json:"emailVerified,omitempty"`
	PhoneNumber          *string                              `json:"phoneNumber,omitempty"`
	PhoneNumberVerified  *bool                                `json:"phoneNumberVerified,omitempty"`
	BirthDate            *string                              `json:"birthDate,omitempty"`
	BirthLocation        *string                              `json:"birthLocation,omitempty"`
	Nationality          *string                              `json:"nationality,omitempty"`
	IDDocumentType       *string                              `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string                              `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string                              `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry    *string                              `json:"idDocumentCountry,omitempty"`
	Locale               *string                              `json:"locale,omitempty"`
	Comment              *string                              `json:"comment,omitempty"`
	Accreditations       []ArchiveAccreditationRepresentation `json:"accreditations,omitempty"`
}

// ArchiveAccreditationRepresentation is a representation of accreditations
type ArchiveAccreditationRepresentation struct {
	Type       *string `json:"type"`
	ExpiryDate *string `json:"expiryDate"`
	Revoked    *bool   `json:"revoked,omitempty"`
}

// ToArchiveUserRepresentation converts a Keycloak user to an ArchiveUserRepresentation
func ToArchiveUserRepresentation(user kc.UserRepresentation) ArchiveUserRepresentation {
	var attrbs = user.Attributes
	var gender, phoneNumber, birthDate, locale *string
	var phoneNumberVerified *bool
	var accreds []ArchiveAccreditationRepresentation

	if attrbs != nil {
		gender = attrbs.GetString(constants.AttrbGender)
		phoneNumber = attrbs.GetString(constants.AttrbPhoneNumber)
		phoneNumberVerified, _ = attrbs.GetBool(constants.AttrbPhoneNumberVerified)
		birthDate = attrbs.GetString(constants.AttrbBirthDate)
		locale = attrbs.GetString(constants.AttrbLocale)
		accreds = stringToAccreditations(attrbs.Get(constants.AttrbAccreditations))
	}
	return ArchiveUserRepresentation{
		ID:                  user.ID,
		Username:            user.Username,
		Gender:              gender,
		FirstName:           user.FirstName,
		LastName:            user.LastName,
		Email:               user.Email,
		EmailVerified:       user.EmailVerified,
		PhoneNumber:         phoneNumber,
		PhoneNumberVerified: phoneNumberVerified,
		BirthDate:           birthDate,
		Locale:              locale,
		Accreditations:      accreds,
	}
}

func stringToAccreditations(values []string) []ArchiveAccreditationRepresentation {
	if len(values) == 0 {
		return nil
	}
	var accreds []ArchiveAccreditationRepresentation
	for _, accredJSON := range values {
		var accred ArchiveAccreditationRepresentation
		if json.Unmarshal([]byte(accredJSON), &accred) == nil {
			accreds = append(accreds, accred)
		}
	}
	return accreds
}

// SetDetails sets user details coming from database in the given ArchiveUserRepresentation
func (u *ArchiveUserRepresentation) SetDetails(dbUser DBUser) {
	u.BirthLocation = dbUser.BirthLocation
	u.Nationality = dbUser.Nationality
	u.IDDocumentType = dbUser.IDDocumentType
	u.IDDocumentNumber = dbUser.IDDocumentNumber
	u.IDDocumentExpiration = dbUser.IDDocumentExpiration
	u.IDDocumentCountry = dbUser.IDDocumentCountry
}
