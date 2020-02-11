package account

import (
	"github.com/cloudtrust/common-service/validation"
	msg "github.com/cloudtrust/keycloak-bridge/internal/messages"
	kc "github.com/cloudtrust/keycloak-client"
)

// AccountRepresentation struct
type AccountRepresentation struct {
	Username             *string `json:"username,omitempty"`
	Email                *string `json:"email,omitempty"`
	Gender               *string `json:"gender,omitempty"`
	FirstName            *string `json:"firstName,omitempty"`
	LastName             *string `json:"lastName,omitempty"`
	PhoneNumber          *string `json:"phoneNumber,omitempty"`
	BirthDate            *string `json:"birthDate,omitempty"`
	BirthLocation        *string `json:"birthLocation,omitempty"`
	IDDocumentType       *string `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string `json:"idDocumentExpiration,omitempty"`
	Locale               *string `json:"locale,omitempty"`
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

// Configuration struct
type Configuration struct {
	ShowAuthenticatorsTab             *bool   `json:"show_authenticators_tab"`
	ShowPasswordTab                   *bool   `json:"show_password_tab"`
	ShowMailEditing                   *bool   `json:"show_mail_editing"`
	ShowAccountDeletionButton         *bool   `json:"show_account_deletion_button"`
	RedirectSuccessfulRegistrationURL *string `json:"redirect_successful_registration_url"`
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
	cred.ID = credKc.Id
	cred.Type = credKc.Type
	cred.UserLabel = credKc.UserLabel
	cred.CreatedDate = credKc.CreatedDate
	cred.CredentialData = credKc.CredentialData
	cred.Temporary = credKc.Temporary
	// credKc.Value is ignored. It may contains secret for legacy credential thus we don't want to transmit it.
	return cred
}

// ConvertToAPIAccount creates an API account representation from  a KC user representation
func ConvertToAPIAccount(userKc kc.UserRepresentation) AccountRepresentation {
	var userRep AccountRepresentation

	userRep.Username = userKc.Username
	userRep.Email = userKc.Email
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName

	if userKc.Attributes != nil {
		var m = *userKc.Attributes

		if value, ok := m["phoneNumber"]; ok && len(value) > 0 {
			userRep.PhoneNumber = &value[0]
		}
		if value, ok := m["gender"]; ok && len(value) > 0 {
			userRep.Gender = &value[0]
		}
		if value, ok := m["birthDate"]; ok && len(value) > 0 {
			userRep.BirthDate = &value[0]
		}
		if value, ok := m["locale"]; ok && len(value) > 0 {
			userRep.Locale = &value[0]
		}
	}
	return userRep
}

// ConvertToKCUser creates a KC user representation from an API user
func ConvertToKCUser(user AccountRepresentation) kc.UserRepresentation {
	var userRep kc.UserRepresentation

	userRep.Username = user.Username
	userRep.Email = user.Email
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName

	var attributes = make(map[string][]string)

	if user.PhoneNumber != nil {
		attributes["phoneNumber"] = []string{*user.PhoneNumber}
	}
	if user.Locale != nil {
		attributes["locale"] = []string{*user.Locale}
	}

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	return userRep
}

// Validators

// Validate is a validator for AccountRepresentation
func (user AccountRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(msg.Username, user.Username, RegExpUsername, false).
		ValidateParameterRegExp(msg.Email, user.Email, RegExpEmail, false).
		ValidateParameterRegExp(msg.Firstname, user.FirstName, RegExpFirstName, false).
		ValidateParameterRegExp(msg.Lastname, user.LastName, RegExpLastName, false).
		ValidateParameterRegExp(msg.PhoneNumber, user.PhoneNumber, RegExpPhoneNumber, false).
		ValidateParameterRegExp(msg.Locale, user.Locale, RegExpLocale, false).
		Status()
}

// Validate is a validator for UpdatePasswordBody
func (updatePwd UpdatePasswordBody) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(msg.CurrentPassword, &updatePwd.CurrentPassword, RegExpPassword, true).
		ValidateParameterRegExp(msg.NewPassword, &updatePwd.NewPassword, RegExpPassword, true).
		ValidateParameterRegExp(msg.ConfirmPassword, &updatePwd.ConfirmPassword, RegExpPassword, true).
		Status()
}

// Validate is a validator for CredentialRepresentation
func (credential CredentialRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(msg.ID, credential.ID, RegExpID, false).
		ValidateParameterRegExp(msg.Type, credential.Type, RegExpType, false).
		ValidateParameterRegExp(msg.Label, credential.UserLabel, RegExpLabel, false).
		Status()
}

// Regular expressions for parameters validation
const (
	RegExpID         = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
	RegExpIDNullable = `^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})|(null)$`
	RegExpLabel      = `^.{0,255}$`
	RegExpType       = `^[a-zA-Z0-9-_]{1,128}$`
	RegExpRealmName  = `^[a-zA-Z0-9_-]{1,36}$`

	// Password
	RegExpPassword = `^.{1,255}$`
	// User
	RegExpUsername    = `^[a-zA-Z0-9-_.]{1,128}$`
	RegExpEmail       = `^.+\@.+\..+`
	RegExpFirstName   = `^.{1,128}$`
	RegExpLastName    = `^.{1,128}$`
	RegExpPhoneNumber = `^\+[1-9]\d{1,14}$`
	RegExpLocale      = `^\w{2}(-\w{2})?$`
)
