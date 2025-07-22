package apikyc

import (
	"context"
	"encoding/json"
	"strings"

	cs "github.com/cloudtrust/common-service/v2"
	cerrors "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/profile"
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
	Dynamic              map[string]any                 `json:"-"`
}

type userAlias UserRepresentation

func (u *userAlias) GetDynamicFields() map[string]any {
	return u.Dynamic
}

func (u *userAlias) SetDynamicFields(dynamicFields map[string]any) {
	u.Dynamic = dynamicFields
}

func (u UserRepresentation) MarshalJSON() ([]byte, error) {
	alias := userAlias(u)
	return keycloakb.DynamicallyMarshalJSON(&alias)
}

func (u *UserRepresentation) UnmarshalJSON(data []byte) error {
	return keycloakb.DynamicallyUnmarshalJSON(data, (*userAlias)(u))
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

// ExportToKeycloak exports user details into a Keycloak UserRepresentation
func (u *UserRepresentation) ExportToKeycloak(kcUser *kc.UserRepresentation, profile kc.UserProfileRepresentation) {
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
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, u.BirthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, u.Nationality)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, u.IDDocumentType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, u.IDDocumentNumber)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, u.IDDocumentExpiration)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, u.IDDocumentCountry)
	attributes.SetDynamicAttributes(u.Dynamic, profile)

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
func (u *UserRepresentation) ImportFromKeycloak(ctx context.Context, kcUser *kc.UserRepresentation, profile kc.UserProfileRepresentation, logger keycloakb.Logger) {
	var phoneNumber = defaultIfNil(kcUser.GetAttributeString(constants.AttrbPhoneNumber), u.PhoneNumber)
	var gender = defaultIfNil(kcUser.GetAttributeString(constants.AttrbGender), u.Gender)
	var birthdate = defaultIfNil(kcUser.GetAttributeString(constants.AttrbBirthDate), u.BirthDate)
	var locale = defaultIfNil(kcUser.GetAttributeString(constants.AttrbLocale), u.Locale)
	var businessID = defaultIfNil(kcUser.GetAttributeString(constants.AttrbBusinessID), u.BusinessID)
	var birthLocation = defaultIfNil(kcUser.GetAttributeString(constants.AttrbBirthLocation), u.BirthLocation)
	var nationality = defaultIfNil(kcUser.GetAttributeString(constants.AttrbNationality), u.Nationality)
	var idDocumentType = defaultIfNil(kcUser.GetAttributeString(constants.AttrbIDDocumentType), u.IDDocumentType)
	var idDocumentNumber = defaultIfNil(kcUser.GetAttributeString(constants.AttrbIDDocumentNumber), u.IDDocumentNumber)
	var idDocumentExpiration = defaultIfNil(kcUser.GetAttributeString(constants.AttrbIDDocumentExpiration), u.IDDocumentExpiration)
	var idDocumentCountry = defaultIfNil(kcUser.GetAttributeString(constants.AttrbIDDocumentCountry), u.IDDocumentCountry)

	var accreditations = u.Accreditations
	var phoneNumberVerified = u.PhoneNumberVerified

	if value, err := kcUser.GetAttributeBool(constants.AttrbPhoneNumberVerified); err == nil && value != nil {
		phoneNumberVerified = value
	}
	if values := kcUser.GetAttribute(constants.AttrbAccreditations); len(values) > 1 || (len(values) == 1 && values[0] != "") {
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
	u.BirthLocation = birthLocation
	u.Nationality = nationality
	u.IDDocumentType = idDocumentType
	u.IDDocumentNumber = idDocumentNumber
	u.IDDocumentExpiration = idDocumentExpiration
	u.IDDocumentCountry = idDocumentCountry
	u.Dynamic = kcUser.GetDynamicAttributes(profile)
}

func defaultIfNil(value *string, defaultValue *string) *string {
	if value != nil {
		return value
	}
	return defaultValue
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate(ctx context.Context, upc profile.UserProfile, realm string) error {
	return validation.NewParameterValidator().
		ValidateParameterFunc(func() error {
			return profile.Validate(ctx, upc, realm, u, "kyc", false)
		}).
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
			// Validate modifies the element
			for i := 0; i < len(*u.Attachments); i++ {
				if err := (*u.Attachments)[i].Validate(); err != nil {
					return err
				}
			}
			return nil
		}).
		Status()
}

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
		return profile.IfNotNil(u.BirthDate)
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
		return profile.IfNotNil(u.IDDocumentExpiration)
	case fields.Locale.AttributeName():
		return profile.IfNotNil(u.Locale)
	case fields.BusinessID.AttributeName():
		return profile.IfNotNil(u.BusinessID)
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
		u.BirthDate = cs.ToStringPtr(value)
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
		u.IDDocumentExpiration = cs.ToStringPtr(value)
		break
	case fields.Locale.AttributeName():
		u.Locale = cs.ToStringPtr(value)
		break
	case fields.BusinessID.AttributeName():
		u.BusinessID = cs.ToStringPtr(value)
		break
	}
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
