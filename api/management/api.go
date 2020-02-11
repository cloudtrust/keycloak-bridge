package management_api

import (
	"strconv"

	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	internal "github.com/cloudtrust/keycloak-bridge/internal/messages"
	kc "github.com/cloudtrust/keycloak-client"
)

// UserRepresentation struct
type UserRepresentation struct {
	ID                  *string   `json:"id,omitempty"`
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
	TrustIDGroups       *[]string `json:"trustIdGroups,omitempty"`
	Roles               *[]string `json:"roles,omitempty"`
	Locale              *string   `json:"locale,omitempty"`
	SmsSent             *int      `json:"smsSent,omitempty"`
}

// UsersPageRepresentation used to manage paging in GetUsers
type UsersPageRepresentation struct {
	Users []UserRepresentation `json:"users"`
	Count *int                 `json:"count"`
}

// RealmRepresentation struct
type RealmRepresentation struct {
	ID              *string `json:"id,omitempty"`
	KeycloakVersion *string `json:"keycloakVersion,omitempty"`
	Realm           *string `json:"realm,omitempty"`
	DisplayName     *string `json:"displayName,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

// ClientRepresentation struct
type ClientRepresentation struct {
	ID       *string `json:"id,omitempty"`
	Name     *string `json:"name,omitempty"`
	BaseURL  *string `json:"baseUrl,omitempty"`
	ClientID *string `json:"clientId,omitempty"`
	Protocol *string `json:"protocol,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

// RequiredActionRepresentation struct
type RequiredActionRepresentation struct {
	Alias         *string `json:"alias,omitempty"`
	DefaultAction *bool   `json:"defaultAction,omitempty"`
	Name          *string `json:"name,omitempty"`
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

// RoleRepresentation struct
type RoleRepresentation struct {
	ClientRole  *bool   `json:"clientRole,omitempty"`
	Composite   *bool   `json:"composite,omitempty"`
	ContainerID *string `json:"containerId,omitempty"`
	Description *string `json:"description,omitempty"`
	ID          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
}

// GroupRepresentation struct
type GroupRepresentation struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// AuthorizationsRepresentation struct
type AuthorizationsRepresentation struct {
	Matrix *map[string]map[string]map[string]struct{} `json:"matrix"`
}

// ActionRepresentation struct
type ActionRepresentation struct {
	Name  *string `json:"name"`
	Scope *string `json:"scope"`
}

// PasswordRepresentation struct
type PasswordRepresentation struct {
	Value *string `json:"value,omitempty"`
}

// RealmCustomConfiguration struct
type RealmCustomConfiguration struct {
	DefaultClientID                     *string   `json:"default_client_id"`
	DefaultRedirectURI                  *string   `json:"default_redirect_uri"`
	APISelfAuthenticatorDeletionEnabled *bool     `json:"api_self_authenticator_deletion_enabled"`
	APISelfPasswordChangeEnabled        *bool     `json:"api_self_password_change_enabled"`
	APISelfMailEditingEnabled           *bool     `json:"api_self_mail_editing_enabled"`
	APISelfAccountDeletionEnabled       *bool     `json:"api_self_account_deletion_enabled"`
	ShowAuthenticatorsTab               *bool     `json:"show_authenticators_tab"`
	ShowPasswordTab                     *bool     `json:"show_password_tab"`
	ShowMailEditing                     *bool     `json:"show_mail_editing"`
	ShowAccountDeletionButton           *bool     `json:"show_account_deletion_button"`
	RegisterExecuteActions              *[]string `json:"register_execute_actions"`
	RedirectCancelledRegistrationURL    *string   `json:"redirect_cancelled_registration_url"`
	RedirectSuccessfulRegistrationURL   *string   `json:"redirect_successful_registration_url"`
}

// FederatedIdentityRepresentation struct
type FederatedIdentityRepresentation struct {
	UserID   *string `json:"userID,omitempty"`
	Username *string `json:"username,omitempty"`
}

// RequiredAction type
type RequiredAction string

// ConvertCredential creates an API credential from a KC credential
func ConvertCredential(credKc *kc.CredentialRepresentation) CredentialRepresentation {
	var cred CredentialRepresentation
	cred.ID = credKc.Id
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

	userRep.ID = userKc.Id
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
		if m["smsSent"] != nil {
			var smsSent = m["smsSent"][0]
			counter, _ := strconv.Atoi(smsSent)
			userRep.SmsSent = &counter
		}

		if m["trustIDGroups"] != nil {
			var trustIDGroups = m["trustIDGroups"]
			userRep.TrustIDGroups = &trustIDGroups
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

// ConvertToKCGroup creates a KC group representation from an API group
func ConvertToKCGroup(group GroupRepresentation) kc.GroupRepresentation {
	return kc.GroupRepresentation{
		Name: group.Name,
	}
}

// ConvertToAPIAuthorizations creates a API authorization representation from an array of DB Authorization
func ConvertToAPIAuthorizations(authorizations []dto.Authorization) AuthorizationsRepresentation {
	var matrix = make(map[string]map[string]map[string]struct{})

	for _, authz := range authorizations {
		_, ok := matrix[*authz.Action]
		if !ok {
			matrix[*authz.Action] = make(map[string]map[string]struct{})
		}

		if authz.TargetRealmID == nil {
			continue
		}

		_, ok = matrix[*authz.Action][*authz.TargetRealmID]
		if !ok {
			matrix[*authz.Action][*authz.TargetRealmID] = make(map[string]struct{})
		}

		if authz.TargetGroupName == nil {
			continue
		}

		matrix[*authz.Action][*authz.TargetRealmID][*authz.TargetGroupName] = struct{}{}
	}

	return AuthorizationsRepresentation{
		Matrix: &matrix,
	}

}

// ConvertToDBAuthorizations creates an array of DB Authorization from an API AuthorizationsRepresentation
func ConvertToDBAuthorizations(realmID, groupID string, apiAuthorizations AuthorizationsRepresentation) []dto.Authorization {
	var authorizations = []dto.Authorization{}

	if apiAuthorizations.Matrix == nil {
		return authorizations
	}

	for action, u := range *apiAuthorizations.Matrix {
		if len(u) == 0 {
			var act = string(action)
			authorizations = append(authorizations, dto.Authorization{
				RealmID:   &realmID,
				GroupName: &groupID,
				Action:    &act,
			})
			continue
		}

		for targetRealmID, v := range u {
			if len(v) == 0 {
				var act = string(action)
				var targetRealm = string(targetRealmID)
				authorizations = append(authorizations, dto.Authorization{
					RealmID:       &realmID,
					GroupName:     &groupID,
					Action:        &act,
					TargetRealmID: &targetRealm,
				})
				continue
			}

			for targetGroupName := range v {
				var act = string(action)
				var targetRealm = string(targetRealmID)
				var targetGroup = string(targetGroupName)
				authorizations = append(authorizations, dto.Authorization{
					RealmID:         &realmID,
					GroupName:       &groupID,
					Action:          &act,
					TargetRealmID:   &targetRealm,
					TargetGroupName: &targetGroup,
				})
			}
		}
	}

	return authorizations
}

// ConvertRequiredAction creates an API requiredAction from a KC requiredAction
func ConvertRequiredAction(ra *kc.RequiredActionProviderRepresentation) RequiredActionRepresentation {
	var raRep RequiredActionRepresentation
	raRep.Alias = ra.Alias
	raRep.Name = ra.Name
	raRep.DefaultAction = ra.DefaultAction

	return raRep
}

// ConvertToKCFedID creates a KC federated identity representation from an API federated identity representation
func ConvertToKCFedID(fedID FederatedIdentityRepresentation) kc.FederatedIdentityRepresentation {
	var kcFedID kc.FederatedIdentityRepresentation

	kcFedID.UserId = fedID.UserID
	kcFedID.UserName = fedID.Username

	return kcFedID
}

// Validators

// Validate is a validator for UserRepresentation
func (user UserRepresentation) Validate() error {
	var v = validation.NewParameterValidator().
		ValidateParameterRegExp(internal.UserID, user.ID, RegExpID, false).
		ValidateParameterRegExp(internal.Username, user.Username, RegExpUsername, false).
		ValidateParameterRegExp(internal.Email, user.Email, RegExpEmail, false).
		ValidateParameterRegExp(internal.Firstname, user.FirstName, RegExpFirstName, false).
		ValidateParameterRegExp(internal.Lastname, user.LastName, RegExpLastName, false).
		ValidateParameterRegExp(internal.PhoneNumber, user.PhoneNumber, RegExpPhoneNumber, false).
		ValidateParameterRegExp(internal.Label, user.Label, RegExpLabel, false).
		ValidateParameterRegExp(internal.Gender, user.Gender, RegExpGender, false).
		ValidateParameterRegExp(internal.Birthdate, user.BirthDate, RegExpBirthDate, false).
		ValidateParameterRegExp(internal.Locale, user.Locale, RegExpLocale, false)

	if user.Groups != nil {
		for _, groupID := range *(user.Groups) {
			v = v.ValidateParameterRegExp(internal.GroupName, &groupID, RegExpID, true)
		}
	}

	if user.Roles != nil {
		for _, roleID := range *(user.Roles) {
			v = v.ValidateParameterRegExp(internal.RoleID, &roleID, RegExpID, true)
		}
	}

	return v.Status()
}

// Validate is a validator for RoleRepresentation
func (role RoleRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(internal.RoleID, role.ID, RegExpID, false).
		ValidateParameterRegExp(internal.Username, role.Name, RegExpName, false).
		ValidateParameterRegExp(internal.Description, role.Description, RegExpDescription, false).
		ValidateParameterRegExp(internal.ContainerID, role.ContainerID, RegExpID, false).
		Status()
}

// Validate is a validator for GroupRepresentation
func (group GroupRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(internal.GroupName, group.ID, RegExpID, false).
		ValidateParameterRegExp(internal.Name, group.Name, RegExpName, false).
		Status()
}

// Validate is a validator for PasswordRepresentation
func (password PasswordRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(internal.Password, password.Value, RegExpPassword, false).
		Status()
}

// Validate is a validator for RealmCustomConfiguration
func (config RealmCustomConfiguration) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(internal.DefaultClientID, config.DefaultClientID, RegExpClientID, false).
		ValidateParameterRegExp(internal.DefaultRedirectURI, config.DefaultRedirectURI, RegExpRedirectURI, false).
		ValidateParameterRegExp(internal.RedirectCancelledRegistrationURL, config.RedirectCancelledRegistrationURL, RegExpRedirectURI, false).
		ValidateParameterRegExp(internal.RedirectSuccessfulRegistrationURL, config.RedirectSuccessfulRegistrationURL, RegExpRedirectURI, false).
		Status()
}

// Validate is a validator for RequiredAction
func (requiredAction RequiredAction) Validate() error {
	if requiredAction != "" {
		var value = string(requiredAction)
		return validation.NewParameterValidator().
			ValidateParameterRegExp(internal.RequiredAction, &value, RegExpRequiredAction, true).
			Status()
	}
	return nil
}

// Validate is a validator for FederatedIdentityRepresentation
func (fedID FederatedIdentityRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(internal.UserID, fedID.UserID, RegExpID, true).
		ValidateParameterRegExp(internal.Username, fedID.Username, RegExpUsername, true).
		Status()
}

// Regular expressions for parameters validation
const (
	RegExpID          = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
	RegExpName        = `^[a-zA-Z0-9-_]{1,128}$`
	RegExpDescription = `^.{1,255}$`

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
