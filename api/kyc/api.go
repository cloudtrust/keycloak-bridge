package apikyc

import (
	"context"
	"encoding/json"
	"strings"

	cerrors "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
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
	Nationality          *string                        `json:"nationality,omitempty"`
	IDDocumentType       *string                        `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string                        `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string                        `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry    *string                        `json:"idDocumentCountry,omitempty"`
	Groups               *[]string                      `json:"groups,omitempty"`
	Locale               *string                        `json:"locale,omitempty"`
	BusinessID           *string                        `json:"businessId,omitempty"`
	Comment              *string                        `json:"comment,omitempty"`
	Accreditations       *[]AccreditationRepresentation `json:"accreditations,omitempty"`
	Attachments          *[]AttachmentRepresentation    `json:"attachments,omitempty"`
}

// AccreditationRepresentation is a representation of accreditations
type AccreditationRepresentation struct {
	Type       *string `json:"type"`
	ExpiryDate *string `json:"expiryDate"`
	Expired    *bool   `json:"expired,omitempty"`
	Revoked    *bool   `json:"revoked,omitempty"`
}

// AttachmentRepresentation is a representation of an attached file
type AttachmentRepresentation struct {
	Filename    *string `json:"filename,omitempty"`
	ContentType *string `json:"contentType,omitempty"`
	Content     *[]byte `json:"content,omitempty"`
}

// Parameter references
const (
	prmUserGender               = "user_gender"
	prmUserFirstName            = "user_firstName"
	prmUserLastName             = "user_lastName"
	prmUserBirthDate            = "user_birthDate"
	prmUserBirthLocation        = "user_birthLocation"
	prmUserNationality          = "user_nationality"
	prmUserIDDocumentType       = "user_idDocType"
	prmUserIDDocumentNumber     = "user_idDocNumber"
	prmUserIDDocumentExpiration = "user_idDocExpiration"
	prmUserIDDocumentCountry    = "user_idDocCountry"
	prmUserLocale               = "user_locale"
	prmUserBusinessID           = "user_businessId"
	prmAttachments              = "attachments"
	prmFilename                 = "attachmentFilename"
	prmContentType              = "attachmentContentType"
	prmContent                  = "attachmentContent"

	regExpMimeType = `^[a-z]+/[\w\d\.+]+$`

	maxNumberAttachments = 6
	minAttachmentSize    = 100
	maxAttachmentSize    = 5 * 1024 * 1024
)

var knownContentTypes = map[string]string{
	"jpg":  "image/jpeg",
	"jpeg": "image/jpeg",
	"pdf":  "application/pdf",
}

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

// ExportToDBUser exports user details into a dto.DBUser
func (u *UserRepresentation) ExportToDBUser(dbUser *dto.DBUser) {
	dbUser.BirthLocation = u.BirthLocation
	dbUser.Nationality = u.Nationality
	dbUser.IDDocumentType = u.IDDocumentType
	dbUser.IDDocumentNumber = u.IDDocumentNumber
	dbUser.IDDocumentExpiration = u.IDDocumentExpiration
	dbUser.IDDocumentCountry = u.IDDocumentCountry
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
	attributes.SetStringWhenNotNil(constants.Locale, u.Locale)
	attributes.SetStringWhenNotNil(constants.AttrbBusinessID, u.BusinessID)

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
	var locale = u.Locale
	var businessID = u.BusinessID

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
		var bFalse = false
		for _, accredJSON := range values {
			var accred AccreditationRepresentation
			if json.Unmarshal([]byte(accredJSON), &accred) == nil {
				accred.Expired = keycloakb.IsDateInThePast(accred.ExpiryDate)
				if accred.Revoked == nil {
					accred.Revoked = &bFalse
				}
				accreds = append(accreds, accred)
			} else {
				logger.Warn(ctx, "msg", "Can't unmarshall JSON", "json", accredJSON)
			}
		}
		accreditations = &accreds
	}
	if value := kcUser.GetAttributeString(constants.AttrbLocale); value != nil {
		locale = value
	}
	if value := kcUser.GetAttributeString(constants.AttrbBusinessID); value != nil {
		businessID = value
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
	u.Locale = locale
	u.BusinessID = businessID
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate(everythingOptional bool) error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmUserGender, u.Gender, constants.RegExpGender, true && !everythingOptional).
		ValidateParameterRegExp(prmUserFirstName, u.FirstName, constants.RegExpFirstName, true && !everythingOptional).
		ValidateParameterRegExp(prmUserLastName, u.LastName, constants.RegExpLastName, true && !everythingOptional).
		ValidateParameterDate(prmUserBirthDate, u.BirthDate, constants.SupportedDateLayouts[0], true && !everythingOptional).
		ValidateParameterRegExp(prmUserBirthLocation, u.BirthLocation, constants.RegExpBirthLocation, false).
		ValidateParameterRegExp(prmUserNationality, u.Nationality, constants.RegExpCountryCode, false).
		ValidateParameterIn(prmUserIDDocumentType, u.IDDocumentType, constants.AllowedDocumentTypes, false).
		ValidateParameterRegExp(prmUserIDDocumentNumber, u.IDDocumentNumber, constants.RegExpIDDocumentNumber, true && !everythingOptional).
		ValidateParameterDate(prmUserIDDocumentExpiration, u.IDDocumentExpiration, constants.SupportedDateLayouts[0], false).
		ValidateParameterRegExp(prmUserIDDocumentCountry, u.IDDocumentCountry, constants.RegExpCountryCode, false).
		ValidateParameterRegExp(prmUserLocale, u.Locale, constants.RegExpLocale, false).
		ValidateParameterRegExp(prmUserBusinessID, u.BusinessID, constants.RegExpBusinessID, false).
		ValidateParameterFunc(func() error {
			var nbAttachments = 0
			if u.Attachments != nil {
				nbAttachments = len(*u.Attachments)
			}
			if nbAttachments == 0 {
				return nil
			}
			if nbAttachments > maxNumberAttachments {
				return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmAttachments)
			}
			for _, attachment := range *u.Attachments {
				if err := attachment.Validate(); err != nil {
					return err
				}
			}
			return nil
		}).
		Status()
}

// Validate an AttachmentRepresentation
func (a *AttachmentRepresentation) Validate() error {
	var err = validation.NewParameterValidator().
		ValidateParameterRegExp(prmContentType, a.ContentType, regExpMimeType, false).
		ValidateParameterNotNil(prmContent, a.Content).
		Status()
	if err != nil {
		return err
	}
	if a.ContentType == nil {
		if a.Filename == nil {
			return cerrors.CreateMissingParameterError(prmContentType)
		}
		a.ContentType = evaluateContentType(*a.Filename)
		if a.ContentType == nil {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmFilename)
		}
	} else if !isKnownContentType(*a.ContentType) {
		return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmContentType)
	}
	if len(*a.Content) < minAttachmentSize || len(*a.Content) > maxAttachmentSize {
		return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmContent)
	}
	return nil
}

func evaluateContentType(filename string) *string {
	var fileSplits = strings.Split(strings.ToLower(filename), ".")
	if contentType, ok := knownContentTypes[fileSplits[len(fileSplits)-1]]; ok {
		return &contentType
	}
	return nil
}

func isKnownContentType(contentType string) bool {
	for _, mimeType := range knownContentTypes {
		if mimeType == contentType {
			return true
		}
	}
	return false
}
