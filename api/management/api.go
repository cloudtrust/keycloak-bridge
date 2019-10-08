package management_api

import (
	"errors"
	"regexp"
	"strconv"

	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// UserRepresentation struct
type UserRepresentation struct {
	Id                  *string   `json:"id,omitempty"`
	Username            *string   `json:"username,omitempty"`
	Email               *string   `json:"email,omitempty"`
	Enabled             *bool     `json:"enabled,omitempty"`
	EmailVerified       *bool     `json:"emailVerified,omitempty"`
	PhoneNumberVerified *bool     `json:"phoneNumberVerified,omitempty"`
	FirstName           *string   `json:"firstName,omitempty"`
	LastName            *string   `json:"lastName,omitempty"`
	PhoneNumber         *string   `json:"phoneNumber,omitempty"`
	Label               *string   `json:"label,omitempty"`
	Gender              *string   `json:"gender,omitempty"`
	BirthDate           *string   `json:"birthDate,omitempty"`
	CreatedTimestamp    *int64    `json:"createdTimestamp,omitempty"`
	Groups              *[]string `json:"groups,omitempty"`
	Roles               *[]string `json:"roles,omitempty"`
	Locale              *string   `json:"locale,omitempty"`
}

// UsersPageRepresentation used to manage paging in GetUsers
type UsersPageRepresentation struct {
	Users []UserRepresentation `json:"users"`
	Count *int                 `json:"count"`
}

// RealmRepresentation struct
type RealmRepresentation struct {
	Id              *string `json:"id,omitempty"`
	KeycloakVersion *string `json:"keycloakVersion,omitempty"`
	Realm           *string `json:"realm,omitempty"`
	DisplayName     *string `json:"displayName,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

// ClientRepresentation struct
type ClientRepresentation struct {
	Id       *string `json:"id,omitempty"`
	Name     *string `json:"name,omitempty"`
	BaseUrl  *string `json:"baseUrl,omitempty"`
	ClientId *string `json:"clientId,omitempty"`
	Protocol *string `json:"protocol,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

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

// RoleRepresentation struct
type RoleRepresentation struct {
	ClientRole  *bool   `json:"clientRole,omitempty"`
	Composite   *bool   `json:"composite,omitempty"`
	ContainerId *string `json:"containerId,omitempty"`
	Description *string `json:"description,omitempty"`
	Id          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
}

// GroupRepresentation struct
type GroupRepresentation struct {
	Id   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// PasswordRepresentation struct
type PasswordRepresentation struct {
	Value *string `json:"value,omitempty"`
}

// RealmCustomConfiguration struct
type RealmCustomConfiguration struct {
	DefaultClientId              *string `json:"default_client_id,omitempty"`
	DefaultRedirectUri           *string `json:"default_redirect_uri,omitempty"`
	SelfAuthenticatorMgmtEnabled *bool   `json:"self_authenticator_mgmt_enabled"`
	SelfPasswordChangeEnabled    *bool   `json:"self_password_change_enabled"`
}

// RequiredAction type
type RequiredAction string

// ConvertCredential creates an API credential from a KC credential
func ConvertCredential(credKc *kc.CredentialRepresentation) CredentialRepresentation {
	var cred CredentialRepresentation
	cred.Id = credKc.Id
	cred.Type = credKc.Type
	cred.UserLabel = credKc.UserLabel
	cred.CreatedDate = credKc.CreatedDate
	cred.CredentialData = credKc.CredentialData
	cred.Temporary = credKc.Temporary
	cred.Value = credKc.Value

	return cred
}

// ConvertToAPIUser creates an API user representation from  a KC user representation
func ConvertToAPIUser(userKc kc.UserRepresentation) UserRepresentation {
	var userRep UserRepresentation

	userRep.Id = userKc.Id
	userRep.Username = userKc.Username
	userRep.Email = userKc.Email
	userRep.Enabled = userKc.Enabled
	userRep.EmailVerified = userKc.EmailVerified
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName
	userRep.CreatedTimestamp = userKc.CreatedTimestamp

	if userKc.Attributes != nil {
		var m = *userKc.Attributes

		if m["phoneNumber"] != nil {
			var phoneNumber = m["phoneNumber"][0]
			userRep.PhoneNumber = &phoneNumber
		}

		if m["label"] != nil {
			var label = m["label"][0]
			userRep.Label = &label
		}

		if m["gender"] != nil {
			var gender = m["gender"][0]
			userRep.Gender = &gender
		}

		if m["birthDate"] != nil {
			var birthDate = m["birthDate"][0]
			userRep.BirthDate = &birthDate
		}

		if m["phoneNumberVerified"] != nil {
			var phoneNumberVerified, _ = strconv.ParseBool(m["phoneNumberVerified"][0])
			userRep.PhoneNumberVerified = &phoneNumberVerified
		}

		if m["locale"] != nil {
			var locale = m["locale"][0]
			userRep.Locale = &locale
		}
	}
	return userRep
}

// ConvertToAPIUsersPage converts paged users results from KC model to API one
func ConvertToAPIUsersPage(users kc.UsersPageRepresentation) UsersPageRepresentation {
	var slice = []UserRepresentation{}
	var count = 0

	for _, u := range users.Users {
		slice = append(slice, ConvertToAPIUser(u))
	}

	if users.Count != nil {
		count = *users.Count
	}
	return UsersPageRepresentation{
		Count: &count,
		Users: slice,
	}
}

// ConvertToKCUser creates a KC user representation from an API user
func ConvertToKCUser(user UserRepresentation) kc.UserRepresentation {
	var userRep kc.UserRepresentation

	userRep.Username = user.Username
	userRep.Email = user.Email
	userRep.Enabled = user.Enabled
	userRep.EmailVerified = user.EmailVerified
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName
	userRep.Groups = user.Groups
	userRep.RealmRoles = user.Roles

	var attributes = make(map[string][]string)

	if user.PhoneNumber != nil {
		attributes["phoneNumber"] = []string{*user.PhoneNumber}
	}

	if user.Label != nil {
		attributes["label"] = []string{*user.Label}
	}

	if user.Gender != nil {
		attributes["gender"] = []string{*user.Gender}
	}

	if user.BirthDate != nil {
		attributes["birthDate"] = []string{*user.BirthDate}
	}

	if user.PhoneNumberVerified != nil {
		attributes["phoneNumberVerified"] = []string{strconv.FormatBool(*user.PhoneNumberVerified)}
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

// Validate is a validator for UserRepresentation
func (user UserRepresentation) Validate() error {
	if user.Id != nil && !matchesRegExp(*user.Id, RegExpID) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.UserID)
	}

	if user.Username != nil && !matchesRegExp(*user.Username, RegExpUsername) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Username)
	}

	if user.Email != nil && !matchesRegExp(*user.Email, RegExpEmail) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Email)
	}

	if user.FirstName != nil && !matchesRegExp(*user.FirstName, RegExpFirstName) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Firstname)
	}

	if user.LastName != nil && !matchesRegExp(*user.LastName, RegExpLastName) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Lastname)
	}

	if user.PhoneNumber != nil && !matchesRegExp(*user.PhoneNumber, RegExpPhoneNumber) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.PhoneNumber)
	}

	if user.Label != nil && !matchesRegExp(*user.Label, RegExpLabel) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Label)
	}

	if user.Gender != nil && !matchesRegExp(*user.Gender, RegExpGender) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Gender)
	}

	if user.BirthDate != nil && !matchesRegExp(*user.BirthDate, RegExpBirthDate) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Birthdate)
	}

	if user.Groups != nil {
		for _, groupID := range *(user.Groups) {
			if !matchesRegExp(groupID, RegExpID) {
				return errors.New(internal.MsgErrInvalidParam + "." + internal.GroudID)
			}
		}
	}

	if user.Roles != nil {
		for _, roleID := range *(user.Roles) {
			if !matchesRegExp(roleID, RegExpID) {
				return errors.New(internal.MsgErrInvalidParam + "." + internal.RoleID)
			}
		}
	}

	if user.Locale != nil && !matchesRegExp(*user.Locale, RegExpLocale) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Locale)
	}

	return nil
}

// Validate is a validator for RoleRepresentation
func (role RoleRepresentation) Validate() error {
	if role.Id != nil && !matchesRegExp(*role.Id, RegExpID) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.RoleID)
	}

	if role.Name != nil && !matchesRegExp(*role.Name, RegExpName) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Username)
	}

	if role.Description != nil && !matchesRegExp(*role.Description, RegExpDescription) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Description)
	}

	if role.ContainerId != nil && !matchesRegExp(*role.ContainerId, RegExpID) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.ContainerID)
	}

	return nil
}

// Validate is a validator for PasswordRepresentation
func (password PasswordRepresentation) Validate() error {
	if password.Value != nil && !matchesRegExp(*password.Value, RegExpPassword) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.Password)
	}

	return nil
}

// Validate is a validator for RealmCustomConfiguration
func (config RealmCustomConfiguration) Validate() error {
	if config.DefaultClientId != nil && !matchesRegExp(*config.DefaultClientId, RegExpClientID) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.DefaultClientID)
	}

	if config.DefaultRedirectUri != nil && !matchesRegExp(*config.DefaultRedirectUri, RegExpRedirectURI) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.DefaultRedirectURI)
	}

	return nil
}

// Validate is a validator for RequiredAction
func (requiredAction RequiredAction) Validate() error {
	if requiredAction != "" && !matchesRegExp(string(requiredAction), RegExpRequiredAction) {
		return errors.New(internal.MsgErrInvalidParam + "." + internal.RequiredAction)
	}

	return nil
}

func matchesRegExp(value, re string) bool {
	res, _ := regexp.MatchString(re, value)
	return res
}

// Regular expressions for parameters validation
const (
	RegExpID = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`

	// Client
	RegExpClientID = `^[a-zA-Z0-9-_.]{1,255}$`

	// User
	RegExpUsername    = `^[a-zA-Z0-9-_.]{1,128}$`
	RegExpEmail       = `^.+\@.+\..+`
	RegExpFirstName   = `^.{1,128}$`
	RegExpLastName    = `^.{1,128}$`
	RegExpPhoneNumber = `^\+[1-9]\d{1,14}$`
	RegExpLabel       = `^.{1,255}$`
	RegExpGender      = `^[MF]$`
	RegExpBirthDate   = `^(\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))$`
	RegExpLocale      = `^[a-z]{2}$`

	// Role
	RegExpName        = `^[a-zA-Z0-9-_]{1,128}$`
	RegExpDescription = `^.{1,255}$`

	// Password
	RegExpPassword = `^.{1,255}$`

	// RealmCustomConfiguration
	RegExpRedirectURI = `^\w+:(\/?\/?)[^\s]+$`

	// RequiredAction
	RegExpRequiredAction = `^[a-zA-Z0-9-_]{1,255}$`

	// Others
	RegExpRealmName = `^[a-zA-Z0-9_-]{1,36}$`
	RegExpSearch    = `^.{1,128}$`
	RegExpLifespan  = `^[0-9]{1,10}$`
	RegExpGroupIds  = `^([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})(,[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}){0,20}$`
	RegExpNumber    = `^\d+$`
)
