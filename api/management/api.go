package apimanagement

import (
	"context"
	"encoding/json"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	"github.com/cloudtrust/common-service/configuration"
	errorhandler "github.com/cloudtrust/common-service/errors"
	csjson "github.com/cloudtrust/common-service/json"
	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/spf13/cast"
)

// UserRepresentation struct
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
	TrustIDGroups        *[]string                      `json:"trustIdGroups,omitempty"`
	Roles                *[]string                      `json:"roles,omitempty"`
	Locale               *string                        `json:"locale,omitempty"`
	BusinessID           *string                        `json:"businessId,omitempty"`
	SmsSent              *int                           `json:"smsSent,omitempty"`
	SmsAttempts          *int                           `json:"smsAttempts,omitempty"`
	Enabled              *bool                          `json:"enabled,omitempty"`
	Label                *string                        `json:"label,omitempty"`
	PendingChecks        *[]string                      `json:"pendingChecks,omitempty"`
	Accreditations       *[]AccreditationRepresentation `json:"accreditations,omitempty"`
	NameID               *string                        `json:"nameId,omitempty"`
	OnboardingCompleted  *bool                          `json:"onboardingCompleted,omitempty"`
	CreatedTimestamp     *int64                         `json:"createdTimestamp,omitempty"`
}

// UpdatableUserRepresentation struct
type UpdatableUserRepresentation struct {
	ID                   *string                        `json:"id,omitempty"`
	Username             *string                        `json:"username,omitempty"`
	Gender               *string                        `json:"gender,omitempty"`
	FirstName            *string                        `json:"firstName,omitempty"`
	LastName             *string                        `json:"lastName,omitempty"`
	Email                csjson.OptionalString          `json:"email,omitempty"`
	EmailVerified        *bool                          `json:"emailVerified,omitempty"`
	PhoneNumber          csjson.OptionalString          `json:"phoneNumber,omitempty"`
	PhoneNumberVerified  *bool                          `json:"phoneNumberVerified,omitempty"`
	BirthDate            *string                        `json:"birthDate,omitempty"`
	BirthLocation        *string                        `json:"birthLocation,omitempty"`
	Nationality          *string                        `json:"nationality,omitempty"`
	IDDocumentType       *string                        `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string                        `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string                        `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry    *string                        `json:"idDocumentCountry,omitempty"`
	Groups               *[]string                      `json:"groups,omitempty"`
	TrustIDGroups        *[]string                      `json:"trustIdGroups,omitempty"`
	Roles                *[]string                      `json:"roles,omitempty"`
	Locale               *string                        `json:"locale,omitempty"`
	BusinessID           csjson.OptionalString          `json:"businessId,omitempty"`
	SmsSent              *int                           `json:"smsSent,omitempty"`
	SmsAttempts          *int                           `json:"smsAttempts,omitempty"`
	Enabled              *bool                          `json:"enabled,omitempty"`
	Label                *string                        `json:"label,omitempty"`
	PendingChecks        *[]string                      `json:"pendingChecks,omitempty"`
	Accreditations       *[]AccreditationRepresentation `json:"accreditations,omitempty"`
	CreatedTimestamp     *int64                         `json:"createdTimestamp,omitempty"`
}

// UserCheck is a representation of a user check
type UserCheck struct {
	Operator  *string `json:"operator,omitempty"`
	CheckDate *string `json:"checkDate,omitempty"`
	Status    *string `json:"status,omitempty"`
	Type      *string `json:"type,omitempty"`
	Nature    *string `json:"nature,omitempty"`
	ProofType *string `json:"proofType,omitempty"`
	Comment   *string `json:"comment,omitempty"`
}

// AccreditationRepresentation is a representation of accreditations
type AccreditationRepresentation struct {
	Type       *string `json:"type"`
	ExpiryDate *string `json:"expiryDate"`
	Revoked    *bool   `json:"revoked,omitempty"`
	Expired    *bool   `json:"expired,omitempty"`
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

// AttackDetectionStatusRepresentation struct
type AttackDetectionStatusRepresentation struct {
	NumFailures   *int64  `json:"numFailures,omitempty"`
	Disabled      *bool   `json:"disabled,omitempty"`
	LastIPFailure *string `json:"lastIPFailure,omitempty"`
	LastFailure   *int64  `json:"lastFailure,omitempty"`
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
	RedirectCancelledRegistrationURL    *string   `json:"redirect_cancelled_registration_url"`
	RedirectSuccessfulRegistrationURL   *string   `json:"redirect_successful_registration_url"`
	OnboardingRedirectURI               *string   `json:"onboarding_redirect_uri"`
	OnboardingClientID                  *string   `json:"onboarding_client_id"`
	SelfRegisterGroupNames              *[]string `json:"self_register_group_names"`
	BarcodeType                         *string   `json:"barcode_type"`
}

// UserStatus struct
type UserStatus struct {
	Email               *string `json:"email,omitempty"`
	Enabled             *bool   `json:"enabled,omitempty"`
	EmailVerified       *bool   `json:"emailVerified,omitempty"`
	PhoneNumberVerified *bool   `json:"phoneNumberVerified,omitempty"`
	OnboardingCompleted *bool   `json:"onboardingCompleted,omitempty"`
	NumberOfCredentials *int    `json:"numberOfCredentials,omitempty"`
}

// BackOffice configuration keys
const (
	BOConfKeyCustomers = "customers"
	BOConfKeyTeams     = "teams"
)

var (
	allowedBoConfKeys    = map[string]bool{BOConfKeyCustomers: true, BOConfKeyTeams: true}
	allowedAdminConfMode = map[string]bool{"trustID": true, "corporate": true}
	allowedBarcodeType   = map[string]bool{"CODE128": true}
)

// BackOfficeConfiguration type
type BackOfficeConfiguration map[string]map[string][]string

// RealmAdminConfiguration struct
type RealmAdminConfiguration struct {
	Mode                     *string                   `json:"mode"`
	AvailableChecks          map[string]bool           `json:"available_checks"`
	Accreditations           []RealmAdminAccreditation `json:"accreditations"`
	SelfRegisterEnabled      *bool                     `json:"self_register_enabled"`
	Theme                    *string                   `json:"theme"`
	NeedVerifiedContact      *bool                     `json:"need_verified_contact"`
	ConsentRequiredSocial    *bool                     `json:"consent_required_social"`
	ConsentRequiredCorporate *bool                     `json:"consent_required_corporate"`
	ShowGlnEditing           *bool                     `json:"show_gln_editing"`
}

// RealmAdminAccreditation struct
type RealmAdminAccreditation struct {
	Type      *string `json:"type"`
	Validity  *string `json:"validity"`
	Condition *string `json:"condition"`
}

// FederatedIdentityRepresentation struct
type FederatedIdentityRepresentation struct {
	UserID   *string `json:"userID,omitempty"`
	Username *string `json:"username,omitempty"`
}

// RequiredAction type
type RequiredAction string

func defaultString(actual *string, defaultValue string) *string {
	if actual == nil {
		return &defaultValue
	}
	return actual
}

func defaultBool(actual *bool, defaultValue bool) *bool {
	if actual == nil {
		return &defaultValue
	}
	return actual
}

func defaultStringArray(actual *[]string, defaultValue []string) *[]string {
	if actual == nil {
		return &defaultValue
	}
	return actual
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
	cred.Value = credKc.Value

	return cred
}

// ConvertAttackDetectionStatus creates a brute force status from a map
func ConvertAttackDetectionStatus(status map[string]interface{}) AttackDetectionStatusRepresentation {
	var res AttackDetectionStatusRepresentation

	res.NumFailures = convertEntryToInt64(&status, "numFailures")
	res.LastFailure = convertEntryToInt64(&status, "lastFailure")
	if value, ok := status["disabled"]; ok && value != nil {
		if conv, err := cast.ToBoolE(value); err == nil {
			res.Disabled = &conv
		}
	}
	if value, ok := status["lastIPFailure"]; ok && value != nil {
		if conv, err := cast.ToStringE(value); err == nil {
			res.LastIPFailure = &conv
		}
	}

	return res
}

func convertEntryToInt64(status *map[string]interface{}, key string) *int64 {
	if value, ok := (*status)[key]; ok && value != nil {
		if conv, err := cast.ToInt64E(value); err == nil {
			return &conv
		}
	}
	return nil
}

// ConvertToAPIUser creates an API user representation from  a KC user representation
func ConvertToAPIUser(ctx context.Context, userKc kc.UserRepresentation, logger keycloakb.Logger) UserRepresentation {
	var userRep UserRepresentation

	userRep.ID = userKc.ID
	userRep.Username = userKc.Username
	userRep.Email = userKc.Email
	userRep.Enabled = userKc.Enabled
	userRep.EmailVerified = userKc.EmailVerified
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName
	userRep.CreatedTimestamp = userKc.CreatedTimestamp
	userRep.PhoneNumber = userKc.GetAttributeString(constants.AttrbPhoneNumber)
	userRep.Label = userKc.GetAttributeString(constants.AttrbLabel)
	userRep.Gender = userKc.GetAttributeString(constants.AttrbGender)
	userRep.BirthDate = userKc.GetAttributeDate(constants.AttrbBirthDate, constants.SupportedDateLayouts)
	userRep.Locale = userKc.GetAttributeString(constants.AttrbLocale)
	userRep.BusinessID = userKc.GetAttributeString(constants.AttrbBusinessID)
	userRep.NameID = userKc.GetAttributeString(constants.AttrbNameID)
	userRep.OnboardingCompleted, _ = userKc.GetAttributeBool(constants.AttrbOnboardingCompleted)

	if value, err := userKc.GetAttributeBool(constants.AttrbPhoneNumberVerified); err == nil && value != nil {
		userRep.PhoneNumberVerified = value
	}
	if value, err := userKc.GetAttributeInt(constants.AttrbSmsSent); err == nil && value != nil {
		userRep.SmsSent = value
	}
	if value, err := userKc.GetAttributeInt(constants.AttrbSmsAttempts); err == nil && value != nil {
		userRep.SmsAttempts = value
	}
	if value := userKc.GetAttribute(constants.AttrbTrustIDGroups); value != nil {
		userRep.TrustIDGroups = &value
	}
	if value := userKc.GetAttributeString(constants.AttrbPendingChecks); value != nil {
		userRep.PendingChecks = keycloakb.GetPendingChecks(value)
	}
	if values := userKc.GetAttribute(constants.AttrbAccreditations); len(values) > 0 {
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
		userRep.Accreditations = &accreds
	}

	return userRep
}

// ConvertToAPIUsersPage converts paged users results from KC model to API one
func ConvertToAPIUsersPage(ctx context.Context, users kc.UsersPageRepresentation, logger keycloakb.Logger) UsersPageRepresentation {
	var slice = []UserRepresentation{}
	var count = 0

	for _, u := range users.Users {
		slice = append(slice, ConvertToAPIUser(ctx, u, logger))
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
	attributes.SetStringWhenNotNil(constants.AttrbBusinessID, user.BusinessID)

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	return userRep
}

// ConvertUpdatableToKCUser creates a KC user representation from an API user
func ConvertUpdatableToKCUser(user UpdatableUserRepresentation) kc.UserRepresentation {
	var userRep kc.UserRepresentation

	userRep.Username = user.Username
	if user.Email.Defined {
		// empty string to remove an email
		userRep.Email = user.Email.ToValue("")
	}
	userRep.Enabled = user.Enabled
	userRep.EmailVerified = user.EmailVerified
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName
	userRep.Groups = user.Groups
	userRep.RealmRoles = user.Roles

	var attributes = make(kc.Attributes)

	if user.PhoneNumber.Defined {
		attributes.SetStringWhenNotNil(constants.AttrbPhoneNumber, user.PhoneNumber.Value)
	}
	attributes.SetBoolWhenNotNil(constants.AttrbPhoneNumberVerified, user.PhoneNumberVerified)
	attributes.SetStringWhenNotNil(constants.AttrbLabel, user.Label)
	attributes.SetStringWhenNotNil(constants.AttrbGender, user.Gender)
	attributes.SetDateWhenNotNil(constants.AttrbBirthDate, user.BirthDate, constants.SupportedDateLayouts)
	attributes.SetStringWhenNotNil(constants.AttrbLocale, user.Locale)
	if user.BusinessID.Defined {
		attributes.SetStringWhenNotNil(constants.AttrbBusinessID, user.BusinessID.Value)
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

	kcFedID.UserID = fedID.UserID
	kcFedID.UserName = fedID.Username

	return kcFedID
}

// CreateDefaultRealmCustomConfiguration creates a default custom configuration
func CreateDefaultRealmCustomConfiguration() RealmCustomConfiguration {
	return ConvertRealmCustomConfigurationFromDBStruct(configuration.RealmConfiguration{})
}

// ConvertRealmCustomConfigurationFromDBStruct converts a RealmCustomConfiguration from DB struct to API struct
func ConvertRealmCustomConfigurationFromDBStruct(config configuration.RealmConfiguration) RealmCustomConfiguration {
	var emptyArray = []string{}
	return RealmCustomConfiguration{
		DefaultClientID:                     config.DefaultClientID,
		DefaultRedirectURI:                  config.DefaultRedirectURI,
		APISelfAuthenticatorDeletionEnabled: defaultBool(config.APISelfAuthenticatorDeletionEnabled, false),
		APISelfPasswordChangeEnabled:        defaultBool(config.APISelfPasswordChangeEnabled, false),
		APISelfAccountEditingEnabled:        defaultBool(config.APISelfAccountEditingEnabled, false),
		APISelfAccountDeletionEnabled:       defaultBool(config.APISelfAccountDeletionEnabled, false),
		ShowAuthenticatorsTab:               defaultBool(config.ShowAuthenticatorsTab, false),
		ShowPasswordTab:                     defaultBool(config.ShowPasswordTab, false),
		ShowProfileTab:                      defaultBool(config.ShowProfileTab, false),
		ShowAccountDeletionButton:           defaultBool(config.ShowAccountDeletionButton, false),
		RedirectCancelledRegistrationURL:    config.RedirectCancelledRegistrationURL,
		RedirectSuccessfulRegistrationURL:   config.RedirectSuccessfulRegistrationURL,
		OnboardingRedirectURI:               config.OnboardingRedirectURI,
		OnboardingClientID:                  config.OnboardingClientID,
		SelfRegisterGroupNames:              defaultStringArray(config.SelfRegisterGroupNames, emptyArray),
		BarcodeType:                         config.BarcodeType,
	}
}

// CreateDefaultRealmAdminConfiguration creates a default admin configuration
func CreateDefaultRealmAdminConfiguration() RealmAdminConfiguration {
	return ConvertRealmAdminConfigurationFromDBStruct(configuration.RealmAdminConfiguration{})
}

// ConvertRealmAdminConfigurationFromDBStruct converts a RealmAdminConfiguration from DB struct to API struct
func ConvertRealmAdminConfigurationFromDBStruct(conf configuration.RealmAdminConfiguration) RealmAdminConfiguration {
	var checks = conf.AvailableChecks
	if checks == nil {
		checks = make(map[string]bool)
	}
	return RealmAdminConfiguration{
		Mode:                     defaultString(conf.Mode, "corporate"),
		AvailableChecks:          checks,
		Accreditations:           ConvertRealmAccreditationsFromDBStruct(conf.Accreditations),
		SelfRegisterEnabled:      defaultBool(conf.SelfRegisterEnabled, false),
		Theme:                    conf.Theme,
		NeedVerifiedContact:      defaultBool(conf.NeedVerifiedContact, true),
		ConsentRequiredSocial:    defaultBool(conf.ConsentRequiredSocial, false),
		ConsentRequiredCorporate: defaultBool(conf.ConsentRequiredCorporate, false),
		ShowGlnEditing:           defaultBool(conf.ShowGlnEditing, false),
	}
}

// ConvertToDBStruct converts a realm admin configuration into its database version
func (rac RealmAdminConfiguration) ConvertToDBStruct() configuration.RealmAdminConfiguration {
	return configuration.RealmAdminConfiguration{
		Mode:                     rac.Mode,
		AvailableChecks:          rac.AvailableChecks,
		Accreditations:           rac.ConvertRealmAccreditationsToDBStruct(),
		SelfRegisterEnabled:      rac.SelfRegisterEnabled,
		Theme:                    rac.Theme,
		NeedVerifiedContact:      rac.NeedVerifiedContact,
		ConsentRequiredSocial:    rac.ConsentRequiredSocial,
		ConsentRequiredCorporate: rac.ConsentRequiredCorporate,
		ShowGlnEditing:           rac.ShowGlnEditing,
	}
}

// ConvertRealmAccreditationsToDBStruct converts a slice of realm admin accreditation into its database version
func (rac RealmAdminConfiguration) ConvertRealmAccreditationsToDBStruct() []configuration.RealmAdminAccreditation {
	if len(rac.Accreditations) == 0 {
		return nil
	}
	var res []configuration.RealmAdminAccreditation
	for _, accred := range rac.Accreditations {
		res = append(res, configuration.RealmAdminAccreditation{
			Type:      accred.Type,
			Validity:  accred.Validity,
			Condition: accred.Condition,
		})
	}
	return res
}

// ConvertRealmAccreditationsFromDBStruct converts an array of accreditation from DB struct to API struct
func ConvertRealmAccreditationsFromDBStruct(accreds []configuration.RealmAdminAccreditation) []RealmAdminAccreditation {
	if len(accreds) == 0 {
		return make([]RealmAdminAccreditation, 0)
	}
	var res []RealmAdminAccreditation
	for _, accred := range accreds {
		res = append(res, RealmAdminAccreditation{
			Type:      accred.Type,
			Validity:  accred.Validity,
			Condition: accred.Condition,
		})
	}
	return res
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
		ValidateParameterRegExp(constants.BirthLocation, user.BirthLocation, constants.RegExpBirthLocation, false).
		ValidateParameterRegExp(constants.Nationality, user.Nationality, constants.RegExpCountryCode, false).
		ValidateParameterRegExp(constants.Locale, user.Locale, constants.RegExpLocale, false).
		ValidateParameterRegExp(constants.BusinessID, user.BusinessID, constants.RegExpBusinessID, false).
		ValidateParameterIn(constants.IDDocumentType, user.IDDocumentType, constants.AllowedDocumentTypes, false).
		ValidateParameterRegExp(constants.IDDocumentNumber, user.IDDocumentNumber, constants.RegExpIDDocumentNumber, false).
		ValidateParameterLength(constants.IDDocumentNumber, user.IDDocumentNumber, 1, 50, false).
		ValidateParameterDateMultipleLayout(constants.IDDocumentExpiration, user.IDDocumentExpiration, constants.SupportedDateLayouts, false).
		ValidateParameterRegExp(constants.IDDocumentCountry, user.IDDocumentCountry, constants.RegExpCountryCode, false)

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

// Validate is a validator for UpdatableUserRepresentation
func (user UpdatableUserRepresentation) Validate() error {
	var v = validation.NewParameterValidator().
		ValidateParameterRegExp(constants.UserID, user.ID, constants.RegExpID, false).
		ValidateParameterRegExp(constants.Username, user.Username, constants.RegExpUsername, false).
		ValidateParameterRegExp(constants.Firstname, user.FirstName, constants.RegExpFirstName, false).
		ValidateParameterRegExp(constants.Lastname, user.LastName, constants.RegExpLastName, false).
		ValidateParameterRegExp(constants.Label, user.Label, constants.RegExpLabel, false).
		ValidateParameterRegExp(constants.Gender, user.Gender, constants.RegExpGender, false).
		ValidateParameterDateMultipleLayout(constants.Birthdate, user.BirthDate, constants.SupportedDateLayouts, false).
		ValidateParameterRegExp(constants.BirthLocation, user.BirthLocation, constants.RegExpBirthLocation, false).
		ValidateParameterRegExp(constants.Nationality, user.Nationality, constants.RegExpCountryCode, false).
		ValidateParameterRegExp(constants.Locale, user.Locale, constants.RegExpLocale, false).
		ValidateParameterRegExp(constants.BusinessID, user.BusinessID.Value, constants.RegExpBusinessID, false).
		ValidateParameterIn(constants.IDDocumentType, user.IDDocumentType, constants.AllowedDocumentTypes, false).
		ValidateParameterRegExp(constants.IDDocumentNumber, user.IDDocumentNumber, constants.RegExpIDDocumentNumber, false).
		ValidateParameterLength(constants.IDDocumentNumber, user.IDDocumentNumber, 1, 50, false).
		ValidateParameterDateMultipleLayout(constants.IDDocumentExpiration, user.IDDocumentExpiration, constants.SupportedDateLayouts, false).
		ValidateParameterRegExp(constants.IDDocumentCountry, user.IDDocumentCountry, constants.RegExpCountryCode, false)

	if user.Email.Defined && user.Email.Value != nil {
		v = v.ValidateParameterRegExp(constants.Email, user.Email.Value, constants.RegExpEmail, false)
	}
	if user.PhoneNumber.Defined && user.PhoneNumber.Value != nil {
		v = v.ValidateParameterRegExp(constants.PhoneNumber, user.PhoneNumber.Value, constants.RegExpPhoneNumber, false)
	}
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
		ValidateParameterRegExp(constants.OnboardingRedirectURI, config.OnboardingRedirectURI, constants.RegExpRedirectURI, false).
		ValidateParameterRegExp(constants.OnboardingClientID, config.OnboardingClientID, constants.RegExpClientID, false).
		ValidateParameterIn(constants.BarcodeType, config.BarcodeType, allowedBarcodeType, false).
		Status()
}

// Validate is a validator for RealmAdminConfiguration
func (rac RealmAdminConfiguration) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterIn("mode", rac.Mode, allowedAdminConfMode, true).
		ValidateParameterFunc(rac.validateAvailableChecks).
		ValidateParameterRegExp("theme", rac.Theme, constants.RegExpTheme, false).
		Status()
}

func (rac RealmAdminConfiguration) validateAvailableChecks() error {
	var accredConditions, err = rac.validateAccreditations()
	if err != nil {
		return err
	}

	for k, v := range rac.AvailableChecks {
		if !validation.IsStringInSlice(configuration.AvailableCheckKeys, k) {
			return errorhandler.CreateBadRequestError(constants.MsgErrInvalidParam + ".available-checks")
		}
		if _, ok := accredConditions[k]; v && !ok {
			return errorhandler.CreateBadRequestError(constants.MsgErrMissingParam + ".accreditations." + k)
		}
	}

	return nil
}

func (rac RealmAdminConfiguration) validateAccreditations() (map[string]bool, error) {
	var accredConditions = make(map[string]bool)
	for _, accred := range rac.Accreditations {
		if err := accred.Validate(); err != nil {
			return nil, err
		}
		accredConditions[*accred.Condition] = true
	}

	return accredConditions, nil
}

// Validate is a validator for RealmAdminAccreditation
func (acc RealmAdminAccreditation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterLargeDuration("validity", acc.Validity, true).
		ValidateParameterNotNil("condition", acc.Condition).
		ValidateParameterFunc(func() error {
			if !validation.IsStringInSlice(configuration.AvailableCheckKeys, *acc.Condition) {
				return errorhandler.CreateBadRequestError(constants.MsgErrInvalidParam + ".condition")
			}
			return nil
		}).
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

// ConvertToAPIUserChecks converts user checks from DB struct to API struct
func ConvertToAPIUserChecks(checks []dto.DBCheck) []UserCheck {
	if len(checks) == 0 {
		return make([]UserCheck, 0)
	}

	var res []UserCheck
	for _, check := range checks {
		var checkDate *string
		if check.DateTime != nil {
			var date = check.DateTime.Format(constants.SupportedDateLayouts[0])
			checkDate = &date
		}

		res = append(res, UserCheck{
			Operator:  check.Operator,
			CheckDate: checkDate,
			Status:    check.Status,
			Type:      check.Type,
			Nature:    check.Nature,
			ProofType: check.ProofType,
			Comment:   check.Comment,
		})
	}
	return res
}
