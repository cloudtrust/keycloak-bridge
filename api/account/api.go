package account

import (
	"errors"
	"regexp"

	msg "github.com/cloudtrust/keycloak-bridge/internal/messages"
	kc "github.com/cloudtrust/keycloak-client"
)

// AccountRepresentation struct
type AccountRepresentation struct {
	Username    *string `json:"username,omitempty"`
	Email       *string `json:"email,omitempty"`
	FirstName   *string `json:"firstName,omitempty"`
	LastName    *string `json:"lastName,omitempty"`
	PhoneNumber *string `json:"phoneNumber,omitempty"`
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

		if m["phoneNumber"] != nil {
			var phoneNumber = m["phoneNumber"][0]
			userRep.PhoneNumber = &phoneNumber
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

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	return userRep
}

// Validators

// Validate is a validator for AccountRepresentation
func (user AccountRepresentation) Validate() error {
	if user.Username != nil && !matchesRegExp(*user.Username, RegExpUsername) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.Username)
	}

	if user.Email != nil && !matchesRegExp(*user.Email, RegExpEmail) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.Email)
	}

	if user.FirstName != nil && !matchesRegExp(*user.FirstName, RegExpFirstName) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.Firstname)
	}

	if user.LastName != nil && !matchesRegExp(*user.LastName, RegExpLastName) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.Lastname)
	}

	if user.PhoneNumber != nil && !matchesRegExp(*user.PhoneNumber, RegExpPhoneNumber) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.PhoneNumber)
	}

	return nil
}

// Validate is a validator for UpdatePasswordBody
func (updatePwd UpdatePasswordBody) Validate() error {
	if !matchesRegExp(updatePwd.CurrentPassword, RegExpPassword) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.CurrentPassword)
	}

	if !matchesRegExp(updatePwd.NewPassword, RegExpPassword) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.NewPassword)
	}

	if !matchesRegExp(updatePwd.ConfirmPassword, RegExpPassword) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.ConfirmPassword)
	}

	return nil
}

// Validate is a validator for CredentialRepresentation
func (credential CredentialRepresentation) Validate() error {
	if credential.ID != nil && !matchesRegExp(*credential.ID, RegExpID) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.ID)
	}

	if credential.Type != nil && !matchesRegExp(*credential.Type, RegExpType) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.Type)
	}

	if credential.UserLabel != nil && !matchesRegExp(*credential.UserLabel, RegExpLabel) {
		return errors.New(msg.MsgErrInvalidParam + "." + msg.Label)
	}

	return nil
}

func matchesRegExp(value, re string) bool {
	res, _ := regexp.MatchString(re, value)
	return res
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
)
