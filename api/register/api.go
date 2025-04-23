package apiregister

import (
	"context"
	"encoding/json"
	"strings"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/profile"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// ActionRepresentation struct
type ActionRepresentation struct {
	Name  *string `json:"name"`
	Scope *string `json:"scope"`
}

// UserRepresentation representation
type UserRepresentation struct {
	Username             *string `json:"username,omitempty"`
	Gender               *string `json:"gender,omitempty"`
	FirstName            *string `json:"firstName,omitempty"`
	LastName             *string `json:"lastName,omitempty"`
	Email                *string `json:"email,omitempty"`
	PhoneNumber          *string `json:"phoneNumber,omitempty"`
	BirthDate            *string `json:"birthDate,omitempty"`
	BirthLocation        *string `json:"birthLocation,omitempty"`
	Nationality          *string `json:"nationality,omitempty"`
	IDDocumentType       *string `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry    *string `json:"idDocumentCountry,omitempty"`
	Locale               *string `json:"locale,omitempty"`
	BusinessID           *string `json:"businessId,omitempty"`
	OnboardingStatus     *string `json:"onboardingStatus,omitempty"`
}

// ConfigurationRepresentation representation
type ConfigurationRepresentation struct {
	RedirectCancelledRegistrationURL *string   `json:"redirect_cancelled_registration_url,omitempty"`
	Mode                             *string   `json:"mode,omitempty"`
	Theme                            *string   `json:"theme,omitempty"`
	SupportedLocales                 *[]string `json:"supportedLocales,omitempty"`
	SelfRegisterEnabled              *bool     `json:"selfRegisterEnabled,omitempty"`
	ContextKey                       *string   `json:"contextKey,omitempty"`
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

// ConvertToKeycloak converts a given User to a Keycloak UserRepresentation
func (u *UserRepresentation) ConvertToKeycloak() kc.UserRepresentation {
	var (
		bTrue      = true
		bFalse     = false
		attributes = make(kc.Attributes)
	)

	attributes.SetStringWhenNotNil(constants.AttrbGender, u.Gender)
	if u.PhoneNumber != nil {
		attributes.SetString(constants.AttrbPhoneNumber, *u.PhoneNumber)
		attributes.SetBool(constants.AttrbPhoneNumberVerified, false)
	}
	attributes.SetDateWhenNotNil(constants.AttrbBirthDate, u.BirthDate, constants.SupportedDateLayouts)
	attributes.SetStringWhenNotNil(constants.AttrbLocale, u.Locale)
	attributes.SetStringWhenNotNil(constants.AttrbBusinessID, u.BusinessID)
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, u.BirthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, u.Nationality)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, u.IDDocumentType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, u.IDDocumentNumber)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, u.IDDocumentExpiration)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, u.IDDocumentCountry)
	attributes.SetStringWhenNotNil(constants.AttrbOnboardingStatus, u.OnboardingStatus)

	return kc.UserRepresentation{
		Username:      u.Username,
		Email:         u.Email,
		EmailVerified: &bFalse,
		Enabled:       &bTrue,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Attributes:    &attributes,
	}
}

// Validate checks the validity of the given User
func (u *UserRepresentation) Validate(ctx context.Context, upc profile.UserProfile, realm string) error {
	return validation.NewParameterValidator().
		ValidateParameterFunc(func() error {
			return profile.Validate(ctx, upc, realm, u, "register", true)
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
	case fields.OnboardingStatus.AttributeName():
		return profile.IfNotNil(u.OnboardingStatus)
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
	case fields.OnboardingStatus.AttributeName():
		u.OnboardingStatus = cs.ToStringPtr(value)
		break
	}
}
