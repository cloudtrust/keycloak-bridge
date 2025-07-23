package apiaccount

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/fields"
	csjson "github.com/cloudtrust/common-service/v2/json"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/profile"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// AccountRepresentation struct
type AccountRepresentation struct {
	Gender                *string                        `json:"gender,omitempty"`
	FirstName             *string                        `json:"firstName,omitempty"`
	LastName              *string                        `json:"lastName,omitempty"`
	Username              *string                        `json:"username,omitempty"`
	Email                 *string                        `json:"email,omitempty"`
	EmailVerified         *bool                          `json:"emailVerified,omitempty"`
	EmailToValidate       *string                        `json:"emailToValidate,omitempty"`
	PhoneNumber           *string                        `json:"phoneNumber,omitempty"`
	PhoneNumberVerified   *bool                          `json:"phoneNumberVerified,omitempty"`
	PhoneNumberToValidate *string                        `json:"phoneNumberToValidate,omitempty"`
	BirthDate             *string                        `json:"birthDate,omitempty"`
	BirthLocation         *string                        `json:"birthLocation,omitempty"`
	Nationality           *string                        `json:"nationality,omitempty"`
	IDDocumentType        *string                        `json:"idDocumentType,omitempty"`
	IDDocumentNumber      *string                        `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration  *string                        `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry     *string                        `json:"idDocumentCountry,omitempty"`
	Locale                *string                        `json:"locale,omitempty"`
	BusinessID            *string                        `json:"businessId,omitempty"`
	PendingChecks         *[]string                      `json:"pendingChecks,omitempty"`
	Accreditations        *[]AccreditationRepresentation `json:"accreditations,omitempty"`
}

// UpdatableAccountRepresentation struct
type UpdatableAccountRepresentation struct {
	Gender               *string                        `json:"gender,omitempty"`
	FirstName            *string                        `json:"firstName,omitempty"`
	LastName             *string                        `json:"lastName,omitempty"`
	Username             *string                        `json:"username,omitempty"`
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
	Locale               *string                        `json:"locale,omitempty"`
	BusinessID           csjson.OptionalString          `json:"businessId,omitempty"`
	Accreditations       *[]AccreditationRepresentation `json:"accreditations,omitempty"`
}

// AccreditationRepresentation is a representation of accreditations
type AccreditationRepresentation struct {
	Type       *string `json:"type"`
	ExpiryDate *string `json:"expiryDate"`
	Expired    *bool   `json:"expired,omitempty"`
	Revoked    *bool   `json:"revoked,omitempty"`
}

// CredentialRepresentation struct
type CredentialRepresentation struct {
	ID             *string `json:"id,omitempty"`
	Type           *string `json:"type,omitempty"`
	UserLabel      *string `json:"userLabel,omitempty"`
	CreatedDate    *int64  `json:"createdDate,omitempty"`
	CredentialData *string `json:"credentialData,omitempty"`
	Value          *string `json:"value,omitempty"`
	Temporary      *bool   `json:"temporary,omitempty"`
}

// LinkedAccountRepresentation struct
type LinkedAccountRepresentation struct {
	Connected      *bool   `json:"connected,omitempty"`
	Social         *bool   `json:"social,omitempty"`
	ProviderAlias  *string `json:"providerAlias,omitempty"`
	ProviderName   *string `json:"providerName,omitempty"`
	DisplayName    *string `json:"displayName,omitempty"`
	LinkedUsername *string `json:"linkedUsername,omitempty"`
}

// Configuration struct
type Configuration struct {
	EditingEnabled                        *bool           `json:"editing_enabled"`
	ShowAuthenticatorsTab                 *bool           `json:"show_authenticators_tab"`
	ShowPasswordTab                       *bool           `json:"show_password_tab"`
	ShowProfileTab                        *bool           `json:"show_profile_tab"`
	ShowAccountDeletionButton             *bool           `json:"show_account_deletion_button"`
	ShowIDPLinksTab                       *bool           `json:"show_idplinks_tab"`
	SelfServiceDefaultTab                 *string         `json:"self_service_default_tab"`
	RedirectSuccessfulRegistrationURL     *string         `json:"redirect_successful_registration_url"`
	AvailableChecks                       map[string]bool `json:"available-checks"`
	BarcodeType                           *string         `json:"barcode_type"`
	Theme                                 *string         `json:"theme"`
	SupportedLocales                      *[]string       `json:"supportedLocales,omitempty"`
	ShowGlnEditing                        *bool           `json:"show_gln_editing,omitempty"`
	VideoIdentificationVoucherEnabled     *bool           `json:"video_identification_voucher_enabled"`
	VideoIdentificationAccountingEnabled  *bool           `json:"video_identification_accounting_enabled"`
	VideoIdentificationPrepaymentRequired *bool           `json:"video_identification_prepayment_required"`
	AutoIdentificationVoucherEnabled      *bool           `json:"auto_identification_voucher_enabled"`
	AutoIdentificationAccountingEnabled   *bool           `json:"auto_identification_accounting_enabled"`
	AutoIdentificationPrepaymentRequired  *bool           `json:"auto_identification_prepayment_required"`
	AllowedBackURLs                       []string        `json:"allowed_back_urls"`
}

// UpdatePasswordBody is the definition of the expected body content of UpdatePassword method
type UpdatePasswordBody struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

// LabelBody struct
type LabelBody struct {
	Label string `json:"label,omitempty"`
}

// ConvertCredential creates an API credential from a KC credential
func ConvertCredential(credKc *kc.CredentialRepresentation) CredentialRepresentation {
	var cred CredentialRepresentation
	cred.ID = credKc.ID
	cred.Type = credKc.Type
	cred.UserLabel = credKc.UserLabel
	cred.CreatedDate = credKc.CreatedDate
	cred.CredentialData = credKc.CredentialData
	cred.Temporary = credKc.Temporary
	// credKc.Value is ignored. It may contains secret for legacy credential thus we don't want to transmit it.
	return cred
}

// ConvertToAPIAccount creates an API account representation from a KC user representation
func ConvertToAPIAccount(ctx context.Context, userKc kc.UserRepresentation, logger keycloakb.Logger) AccountRepresentation {
	var userRep AccountRepresentation

	userRep.Username = userKc.Username
	userRep.Email = userKc.Email
	userRep.EmailVerified = userKc.EmailVerified
	userRep.EmailToValidate = userKc.GetAttributeString(constants.AttrbEmailToValidate)
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName
	userRep.PhoneNumber = userKc.GetAttributeString(constants.AttrbPhoneNumber)
	userRep.PhoneNumberToValidate = userKc.GetAttributeString(constants.AttrbPhoneNumberToValidate)
	userRep.Gender = userKc.GetAttributeString(constants.AttrbGender)
	userRep.Locale = userKc.GetAttributeString(constants.AttrbLocale)
	userRep.BusinessID = userKc.GetAttributeString(constants.AttrbBusinessID)
	userRep.BirthLocation = userKc.GetAttributeString(constants.AttrbBirthLocation)
	userRep.Nationality = userKc.GetAttributeString(constants.AttrbNationality)
	userRep.IDDocumentType = userKc.GetAttributeString(constants.AttrbIDDocumentType)
	userRep.IDDocumentNumber = userKc.GetAttributeString(constants.AttrbIDDocumentNumber)
	userRep.IDDocumentExpiration = userKc.GetAttributeString(constants.AttrbIDDocumentExpiration)
	userRep.IDDocumentCountry = userKc.GetAttributeString(constants.AttrbIDDocumentCountry)

	if verified, err := userKc.GetAttributeBool(constants.AttrbPhoneNumberVerified); err == nil && verified != nil {
		userRep.PhoneNumberVerified = verified
	}
	if value := userKc.GetAttributeDate(constants.AttrbBirthDate, constants.SupportedDateLayouts); value != nil {
		userRep.BirthDate = value
	}
	if values := userKc.GetAttribute(constants.AttrbAccreditations); len(values) > 0 {
		userRep.Accreditations = convertToAccreditations(ctx, values, logger)
	}

	return userRep
}

// ConvertAPILinkedAccount creates an API linked account from a KC linked account
func ConvertAPILinkedAccount(accountKc *kc.LinkedAccountRepresentation) LinkedAccountRepresentation {
	return LinkedAccountRepresentation{
		Connected:      accountKc.Connected,
		Social:         accountKc.Social,
		ProviderAlias:  accountKc.ProviderAlias,
		ProviderName:   accountKc.ProviderName,
		DisplayName:    accountKc.DisplayName,
		LinkedUsername: accountKc.LinkedUsername,
	}
}

func convertToAccreditations(ctx context.Context, values []string, logger keycloakb.Logger) *[]AccreditationRepresentation {
	var accreds []AccreditationRepresentation
	var bFalse = false
	if len(values) > 0 && !(len(values) == 1 && values[0] == "") {
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
	}
	return &accreds
}

func defaultStringPtr(value *string, defaultValue *string) *string {
	if value != nil {
		return value
	}
	return defaultValue
}

// MergeUserWithoutEmailAndPhoneNumber merge new values into existing KC user representation
func MergeUserWithoutEmailAndPhoneNumber(userRep *kc.UserRepresentation, user UpdatableAccountRepresentation) {
	// This merge function does not care about contacts (email, phoneNumber)
	userRep.Username = defaultStringPtr(user.Username, userRep.Username)
	userRep.FirstName = defaultStringPtr(user.FirstName, userRep.FirstName)
	userRep.LastName = defaultStringPtr(user.LastName, userRep.LastName)

	var attributes = make(kc.Attributes)
	if userRep.Attributes != nil {
		attributes = *userRep.Attributes
	}
	attributes.SetStringWhenNotNil(constants.AttrbLocale, user.Locale)
	if user.BusinessID.Defined {
		if user.BusinessID.Value != nil {
			attributes.SetStringWhenNotNil(constants.AttrbBusinessID, user.BusinessID.Value)
		} else {
			attributes.Remove(constants.AttrbBusinessID)
		}
	}
	attributes.SetStringWhenNotNil(constants.AttrbBirthDate, user.BirthDate)
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, user.BirthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, user.Nationality)
	attributes.SetStringWhenNotNil(constants.AttrbGender, user.Gender)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, user.IDDocumentType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, user.IDDocumentNumber)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, user.IDDocumentExpiration)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, user.IDDocumentCountry)

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}
}

// Validators

// GetField is used to validate a user against a UserProfile
func (user *UpdatableAccountRepresentation) GetField(field string) interface{} {
	switch field {
	case fields.Username.Key():
		return profile.IfNotNil(user.Username)
	case fields.Email.Key():
		return profile.IfNotNil(user.Email)
	case fields.FirstName.Key():
		return profile.IfNotNil(user.FirstName)
	case fields.LastName.Key():
		return profile.IfNotNil(user.LastName)
	case fields.Gender.AttributeName():
		return profile.IfNotNil(user.Gender)
	case fields.PhoneNumber.AttributeName():
		return profile.IfNotNil(user.PhoneNumber)
	case fields.BirthDate.AttributeName():
		return profile.IfNotNil(user.BirthDate)
	case fields.BirthLocation.AttributeName():
		return profile.IfNotNil(user.BirthLocation)
	case fields.Nationality.AttributeName():
		return profile.IfNotNil(user.Nationality)
	case fields.IDDocumentType.AttributeName():
		return profile.IfNotNil(user.IDDocumentType)
	case fields.IDDocumentNumber.AttributeName():
		return profile.IfNotNil(user.IDDocumentNumber)
	case fields.IDDocumentCountry.AttributeName():
		return profile.IfNotNil(user.IDDocumentCountry)
	case fields.IDDocumentExpiration.AttributeName():
		return profile.IfNotNil(user.IDDocumentExpiration)
	case fields.Locale.AttributeName():
		return profile.IfNotNil(user.Locale)
	case fields.BusinessID.AttributeName():
		if user.BusinessID.Defined {
			return profile.IfNotNil(user.BusinessID.Value)
		}
		return nil
	default:
		return nil
	}
}

// SetField is used to validate a user against a UserProfile
func (user *UpdatableAccountRepresentation) SetField(field string, value interface{}) {
	switch field {
	case fields.Username.Key():
		user.Username = cs.ToStringPtr(value)
		break
	case fields.Email.Key():
		user.Email = cs.ToStringPtr(value)
		break
	case fields.FirstName.Key():
		user.FirstName = cs.ToStringPtr(value)
		break
	case fields.LastName.Key():
		user.LastName = cs.ToStringPtr(value)
		break
	case fields.Gender.AttributeName():
		user.Gender = cs.ToStringPtr(value)
		break
	case fields.PhoneNumber.AttributeName():
		user.PhoneNumber = cs.ToStringPtr(value)
		break
	case fields.BirthDate.AttributeName():
		user.BirthDate = cs.ToStringPtr(value)
		break
	case fields.BirthLocation.AttributeName():
		user.BirthLocation = cs.ToStringPtr(value)
		break
	case fields.Nationality.AttributeName():
		user.Nationality = cs.ToStringPtr(value)
		break
	case fields.IDDocumentType.AttributeName():
		user.IDDocumentType = cs.ToStringPtr(value)
		break
	case fields.IDDocumentNumber.AttributeName():
		user.IDDocumentNumber = cs.ToStringPtr(value)
		break
	case fields.IDDocumentCountry.AttributeName():
		user.IDDocumentCountry = cs.ToStringPtr(value)
		break
	case fields.IDDocumentExpiration.AttributeName():
		user.IDDocumentExpiration = cs.ToStringPtr(value)
		break
	case fields.Locale.AttributeName():
		user.Locale = cs.ToStringPtr(value)
		break
	case fields.BusinessID.AttributeName():
		user.BusinessID.Value = cs.ToStringPtr(value)
		user.BusinessID.Defined = user.BusinessID.Value != nil
		break
	}
}

// Validate validates an incoming account against a user profile
func (user *UpdatableAccountRepresentation) Validate(ctx context.Context, upc profile.UserProfile, realm string) error {
	return validation.NewParameterValidator().
		ValidateParameterFunc(func() error {
			return profile.Validate(ctx, upc, realm, user, "account", false)
		}).
		Status()
}

// Validate is a validator for UpdatePasswordBody
func (updatePwd UpdatePasswordBody) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(constants.CurrentPassword, &updatePwd.CurrentPassword, constants.RegExpPassword, true).
		ValidateParameterRegExp(constants.NewPassword, &updatePwd.NewPassword, constants.RegExpPassword, true).
		ValidateParameterRegExp(constants.ConfirmPassword, &updatePwd.ConfirmPassword, constants.RegExpPassword, true).
		Status()
}

// Validate is a validator for CredentialRepresentation
func (credential CredentialRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(constants.ID, credential.ID, constants.RegExpID, false).
		ValidateParameterRegExp(constants.Type, credential.Type, RegExpType, false).
		ValidateParameterRegExp(constants.Label, credential.UserLabel, RegExpLabel, false).
		Status()
}

// Regular expressions for parameters validation
const (
	RegExpIDNullable = `^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})$|^(null)$`
	RegExpLabel      = `^.{0,255}$`
	RegExpType       = `^[a-zA-Z0-9-_]{1,128}$`
)
