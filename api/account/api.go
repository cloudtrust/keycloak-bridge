package account_api

import (
	"errors"
	"regexp"

	kc "github.com/cloudtrust/keycloak-client"
)

// CredentialRepresentation struct
type CredentialRepresentation struct {
	Id             *string `json:"id,omitempty"`
	Type           *string `json:"type,omitempty"`
	UserLabel      *string `json:"userLabel,omitempty"`
	CreatedDate    *int64  `json:"createdDate,omitempty"`
	CredentialData *string `json:"credentialData,omitempty"`
	Value          *string `json:"value,omitempty"`
	Temporary      *bool   `json:"temporary,omitempty"`
}

// UpdatePasswordBody is the definition of the expected body content of UpdatePassword method
type UpdatePasswordBody struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

type LabelBody struct {
	Label string `json:"label,omitempty"`
}

// ConvertCredential creates an API credential from a KC credential
func ConvertCredential(credKc *kc.CredentialRepresentation) CredentialRepresentation {
	var cred CredentialRepresentation
	cred.Id = credKc.Id
	cred.Type = credKc.Type
	cred.UserLabel = credKc.UserLabel
	cred.CreatedDate = credKc.CreatedDate
	cred.CredentialData = credKc.CredentialData
	cred.Temporary = credKc.Temporary
	return cred
}

// Validate is a validator for UpdatePasswordBody
func (updatePwd UpdatePasswordBody) Validate() error {
	if !matchesRegExp(updatePwd.CurrentPassword, RegExpPassword) {
		return errors.New("Invalid current Password")
	}

	if !matchesRegExp(updatePwd.NewPassword, RegExpPassword) {
		return errors.New("Invalid new Password")
	}

	if !matchesRegExp(updatePwd.ConfirmPassword, RegExpPassword) {
		return errors.New("Invalid confirm Password")
	}

	return nil
}

// Validate is a validator for CredentialRepresentation
func (credential CredentialRepresentation) Validate() error {
	if credential.Id != nil && !matchesRegExp(*credential.Id, RegExpID) {
		return errors.New("Invalid Id")
	}

	if credential.Type != nil && !matchesRegExp(*credential.Type, RegExpType) {
		return errors.New("Invalid Type")
	}

	if credential.UserLabel != nil && !matchesRegExp(*credential.UserLabel, RegExpLabel) {
		return errors.New("Invalid Label")
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
	RegExpLabel      = `^.{1,255}$`
	RegExpType       = `^[a-zA-Z0-9-_]{1,128}$`

	// Password
	RegExpPassword = `^.{1,255}$`
)
