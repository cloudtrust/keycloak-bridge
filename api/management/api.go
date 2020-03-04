package management_api

import (
	"encoding/json"
	"strconv"

	errorhandler "github.com/cloudtrust/common-service/errors"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
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
	APISelfAccountEditingEnabled        *bool     `json:"api_self_account_editing_enabled"`
	APISelfAccountDeletionEnabled       *bool     `json:"api_self_account_deletion_enabled"`
	ShowAuthenticatorsTab               *bool     `json:"show_authenticators_tab"`
	ShowPasswordTab                     *bool     `json:"show_password_tab"`
	ShowProfileTab                      *bool     `json:"show_profile_tab"`
	ShowAccountDeletionButton           *bool     `json:"show_account_deletion_button"`
	RegisterExecuteActions              *[]string `json:"register_execute_actions"`
	RedirectCancelledRegistrationURL    *string   `json:"redirect_cancelled_registration_url"`
	RedirectSuccessfulRegistrationURL   *string   `json:"redirect_successful_registration_url"`
}

// BackOffice configuration keys
const (
	BOConfKeyCustomers = "customers"
	BOConfKeyTeams     = "teams"
)

var allowedBoConfKeys = map[string]bool{BOConfKeyCustomers: true, BOConfKeyTeams: true}

// BackOfficeConfiguration type
type BackOfficeConfiguration map[string]map[string][]string

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

	var attributes = make(kc.Attributes)

	attributes.SetStringWhenNotNil(constants.AttrbPhoneNumber, user.PhoneNumber)
	attributes.SetBoolWhenNotNil(constants.AttrbPhoneNumberVerified, user.PhoneNumberVerified)
	attributes.SetStringWhenNotNil(constants.AttrbLabel, user.Label)
	attributes.SetStringWhenNotNil(constants.AttrbGender, user.Gender)
	attributes.SetDateWhenNotNil(constants.AttrbBirthDate, user.BirthDate, constants.SupportedDateLayouts)
	attributes.SetStringWhenNotNil(constants.AttrbLocale, user.Locale)

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
func ConvertToAPIAuthorizations(authorizations []configuration.Authorization) AuthorizationsRepresentation {
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
func ConvertToDBAuthorizations(realmID, groupName string, apiAuthorizations AuthorizationsRepresentation) []configuration.Authorization {
	var authorizations = []configuration.Authorization{}

	if apiAuthorizations.Matrix == nil {
		return authorizations
	}

	for action, u := range *apiAuthorizations.Matrix {
		if len(u) == 0 {
			var act = string(action)
			authorizations = append(authorizations, configuration.Authorization{
				RealmID:   &realmID,
				GroupName: &groupName,
				Action:    &act,
			})
			continue
		}

		for targetRealmID, v := range u {
			if len(v) == 0 {
				var act = string(action)
				var targetRealm = string(targetRealmID)
				authorizations = append(authorizations, configuration.Authorization{
					RealmID:       &realmID,
					GroupName:     &groupName,
					Action:        &act,
					TargetRealmID: &targetRealm,
				})
				continue
			}

			for targetGroupName := range v {
				var act = string(action)
				var targetRealm = string(targetRealmID)
				var targetGroup = string(targetGroupName)
				authorizations = append(authorizations, configuration.Authorization{
					RealmID:         &realmID,
					GroupName:       &groupName,
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

// NewBackOfficeConfigurationFromJSON creates and validates a new BackOfficeConfiguration from a JSON value
func NewBackOfficeConfigurationFromJSON(confJSON string) (BackOfficeConfiguration, error) {
	var boConf BackOfficeConfiguration
	var err = json.Unmarshal([]byte(confJSON), &boConf)
	if err != nil {
		return BackOfficeConfiguration{}, errorhandler.CreateBadRequestError(errorhandler.MsgErrInvalidQueryParam + ".body")
	}

	var validator = validation.NewParameterValidator()
	for _, realmConf := range boConf {
		for keyBoConf, valueBoConf := range realmConf {
			validator = validator.ValidateParameterIn("body.userType", &keyBoConf, allowedBoConfKeys, true).
				ValidateParameterNotNil("body.allowedGroups", &valueBoConf)
		}
	}

	return boConf, validator.Status()
}

// Validate is a validator for UserRepresentation
func (user UserRepresentation) Validate() error {
	var v = validation.NewParameterValidator().
		ValidateParameterRegExp(constants.UserID, user.ID, constants.RegExpID, false).
		ValidateParameterRegExp(constants.Username, user.Username, constants.RegExpUsername, false).
		ValidateParameterRegExp(constants.Email, user.Email, constants.RegExpEmail, false).
		ValidateParameterRegExp(constants.Firstname, user.FirstName, constants.RegExpFirstName, false).
		ValidateParameterRegExp(constants.Lastname, user.LastName, constants.RegExpLastName, false).
		ValidateParameterRegExp(constants.PhoneNumber, user.PhoneNumber, constants.RegExpPhoneNumber, false).
		ValidateParameterRegExp(constants.Label, user.Label, constants.RegExpLabel, false).
		ValidateParameterRegExp(constants.Gender, user.Gender, constants.RegExpGender, false).
		ValidateParameterDateMultipleLayout(constants.Birthdate, user.BirthDate, constants.SupportedDateLayouts, false).
		ValidateParameterRegExp(constants.Locale, user.Locale, constants.RegExpLocale, false)

	if user.Groups != nil {
		for _, groupID := range *(user.Groups) {
			v = v.ValidateParameterRegExp(constants.GroupID, &groupID, constants.RegExpID, true)
		}
	}

	if user.Roles != nil {
		for _, roleID := range *(user.Roles) {
			v = v.ValidateParameterRegExp(constants.RoleID, &roleID, constants.RegExpID, true)
		}
	}

	return v.Status()
}

// Validate is a validator for RoleRepresentation
func (role RoleRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(constants.RoleID, role.ID, constants.RegExpID, false).
		ValidateParameterRegExp(constants.Username, role.Name, constants.RegExpName, false).
		ValidateParameterRegExp(constants.Description, role.Description, constants.RegExpDescription, false).
		ValidateParameterRegExp(constants.ContainerID, role.ContainerID, constants.RegExpID, false).
		Status()
}

// Validate is a validator for GroupRepresentation
func (group GroupRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(constants.GroupName, group.ID, constants.RegExpID, false).
		ValidateParameterRegExp(constants.Name, group.Name, constants.RegExpName, false).
		Status()
}

// Validate is a validator for PasswordRepresentation
func (password PasswordRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(constants.Password, password.Value, constants.RegExpPassword, false).
		Status()
}

// Validate is a validator for RealmCustomConfiguration
func (config RealmCustomConfiguration) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(constants.DefaultClientID, config.DefaultClientID, constants.RegExpClientID, false).
		ValidateParameterRegExp(constants.DefaultRedirectURI, config.DefaultRedirectURI, constants.RegExpRedirectURI, false).
		ValidateParameterRegExp(constants.RedirectCancelledRegistrationURL, config.RedirectCancelledRegistrationURL, constants.RegExpRedirectURI, false).
		ValidateParameterRegExp(constants.RedirectSuccessfulRegistrationURL, config.RedirectSuccessfulRegistrationURL, constants.RegExpRedirectURI, false).
		Status()
}

// Validate is a validator for RequiredAction
func (requiredAction RequiredAction) Validate() error {
	if requiredAction != "" {
		var value = string(requiredAction)
		return validation.NewParameterValidator().
			ValidateParameterRegExp(constants.RequiredAction, &value, constants.RegExpRequiredAction, true).
			Status()
	}
	return nil
}

// Validate is a validator for FederatedIdentityRepresentation
func (fedID FederatedIdentityRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(constants.UserID, fedID.UserID, constants.RegExpID, true).
		ValidateParameterRegExp(constants.Username, fedID.Username, constants.RegExpUsername, true).
		Status()
}

// Regular expressions for parameters validation
const (
	RegExpID          = constants.RegExpID
	RegExpName        = constants.RegExpName
	RegExpDescription = constants.RegExpDescription

	// Client
	RegExpClientID = constants.RegExpClientID

	// User
	RegExpUsername    = constants.RegExpUsername
	RegExpEmail       = constants.RegExpEmail
	RegExpFirstName   = constants.RegExpFirstName
	RegExpLastName    = constants.RegExpLastName
	RegExpPhoneNumber = constants.RegExpPhoneNumber
	RegExpLabel       = constants.RegExpLabel
	RegExpGender      = constants.RegExpGender
	RegExpLocale      = constants.RegExpLocale

	// Password
	RegExpPassword = constants.RegExpPassword

	// RealmCustomConfiguration
	RegExpRedirectURI = constants.RegExpRedirectURI

	// RequiredAction
	RegExpRequiredAction = constants.RegExpRequiredAction

	// Others
	RegExpRealmName = constants.RegExpRealmName
	RegExpSearch    = constants.RegExpSearch
	RegExpLifespan  = constants.RegExpLifespan
	RegExpGroupIds  = constants.RegExpGroupIds
	RegExpNumber    = constants.RegExpNumber
)
