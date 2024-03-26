package apimanagement

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/fields"
	csjson "github.com/cloudtrust/common-service/v2/json"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	"github.com/cloudtrust/keycloak-bridge/internal/profile"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/spf13/cast"
)

// UserRepresentation struct
type UserRepresentation struct {
	ID                    *string                        `json:"id,omitempty"`
	Username              *string                        `json:"username,omitempty"`
	Gender                *string                        `json:"gender,omitempty"`
	FirstName             *string                        `json:"firstName,omitempty"`
	LastName              *string                        `json:"lastName,omitempty"`
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
	Groups                *[]string                      `json:"groups,omitempty"`
	TrustIDGroups         *[]string                      `json:"trustIdGroups,omitempty"`
	Roles                 *[]string                      `json:"roles,omitempty"`
	Locale                *string                        `json:"locale,omitempty"`
	BusinessID            *string                        `json:"businessId,omitempty"`
	SmsSent               *int                           `json:"smsSent,omitempty"`
	SmsAttempts           *int                           `json:"smsAttempts,omitempty"`
	Enabled               *bool                          `json:"enabled,omitempty"`
	Label                 *string                        `json:"label,omitempty"`
	PendingChecks         *[]string                      `json:"pendingChecks,omitempty"`
	Accreditations        *[]AccreditationRepresentation `json:"accreditations,omitempty"`
	NameID                *string                        `json:"nameId,omitempty"`
	OnboardingCompleted   *bool                          `json:"onboardingCompleted,omitempty"`
	CreatedTimestamp      *int64                         `json:"createdTimestamp,omitempty"`
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

// AuthorizationMessage struct
type AuthorizationMessage struct {
	Authorized bool
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
	SelfServiceDefaultTab               *string   `json:"self_service_default_tab"`
	RedirectCancelledRegistrationURL    *string   `json:"redirect_cancelled_registration_url"`
	RedirectSuccessfulRegistrationURL   *string   `json:"redirect_successful_registration_url"`
	OnboardingRedirectURI               *string   `json:"onboarding_redirect_uri"`
	OnboardingClientID                  *string   `json:"onboarding_client_id"`
	SelfRegisterGroupNames              *[]string `json:"self_register_group_names"`
	BarcodeType                         *string   `json:"barcode_type"`
	AllowedBackURL                      *string   `json:"allowed_back_url"`
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

	regExpSseTabName = `^[a-z]+(-[a-z]+)*$`
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
	Mode                                  *string         `json:"mode"`
	AvailableChecks                       map[string]bool `json:"available_checks"`
	SelfRegisterEnabled                   *bool           `json:"self_register_enabled"`
	BoTheme                               *string         `json:"bo_theme"`
	SseTheme                              *string         `json:"sse_theme"`
	RegisterTheme                         *string         `json:"register_theme"`
	SignerTheme                           *string         `json:"signer_theme"`
	NeedVerifiedContact                   *bool           `json:"need_verified_contact"`
	ConsentRequiredSocial                 *bool           `json:"consent_required_social"`
	ConsentRequiredCorporate              *bool           `json:"consent_required_corporate"`
	ShowGlnEditing                        *bool           `json:"show_gln_editing"`
	BusinessIDIsNotGLN                    *bool           `json:"business_id_is_not_gln"`
	VideoIdentificationVoucherEnabled     *bool           `json:"video_identification_voucher_enabled"`
	VideoIdentificationAccountingEnabled  *bool           `json:"video_identification_accounting_enabled"`
	VideoIdentificationPrepaymentRequired *bool           `json:"video_identification_prepayment_required"`
	AutoIdentificationVoucherEnabled      *bool           `json:"auto_identification_voucher_enabled"`
	AutoIdentificationAccountingEnabled   *bool           `json:"auto_identification_accounting_enabled"`
	AutoIdentificationPrepaymentRequired  *bool           `json:"auto_identification_prepayment_required"`
}

// RealmAdminAccreditation struct
type RealmAdminAccreditation struct {
	Type      *string `json:"type"`
	Validity  *string `json:"validity"`
	Condition *string `json:"condition"`
}

// FederatedIdentityRepresentation struct
type FederatedIdentityRepresentation struct {
	UserID           *string `json:"userID,omitempty"`
	Username         *string `json:"username,omitempty"`
	IdentityProvider *string `json:"identityProvider,omitempty"`
}

// IdentityProviderRepresentation struct
type IdentityProviderRepresentation struct {
	AddReadTokenRoleOnCreate  *bool                   `json:"addReadTokenRoleOnCreate,omitempty"`
	Alias                     *string                 `json:"alias,omitempty"`
	AuthenticateByDefault     *bool                   `json:"authenticateByDefault,omitempty"`
	Config                    *map[string]interface{} `json:"config,omitempty"`
	DisplayName               *string                 `json:"displayName,omitempty"`
	Enabled                   *bool                   `json:"enabled,omitempty"`
	FirstBrokerLoginFlowAlias *string                 `json:"firstBrokerLoginFlowAlias,omitempty"`
	InternalID                *string                 `json:"internalId,omitempty"`
	LinkOnly                  *bool                   `json:"linkOnly,omitempty"`
	PostBrokerLoginFlowAlias  *string                 `json:"postBrokerLoginFlowAlias,omitempty"`
	ProviderID                *string                 `json:"providerId,omitempty"`
	StoreToken                *bool                   `json:"storeToken,omitempty"`
	TrustEmail                *bool                   `json:"trustEmail,omitempty"`
}

// RequiredAction type
type RequiredAction string

func defaultString(actual *string, defaultValue string) *string {
	return defaultStringPtr(actual, &defaultValue)
}

func defaultStringPtr(actual *string, defaultValue *string) *string {
	if actual == nil {
		return defaultValue
	}
	return actual
}

func defaultBool(actual *bool, defaultValue bool) *bool {
	return defaultBoolPtr(actual, &defaultValue)
}

func defaultBoolPtr(actual *bool, defaultValue *bool) *bool {
	if actual == nil {
		return defaultValue
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
	userRep.Enabled = userKc.Enabled
	userRep.Email = userKc.Email
	userRep.EmailToValidate = userKc.GetAttributeString(constants.AttrbEmailToValidate)
	userRep.EmailVerified = userKc.EmailVerified
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName
	userRep.CreatedTimestamp = userKc.CreatedTimestamp
	userRep.PhoneNumber = userKc.GetAttributeString(constants.AttrbPhoneNumber)
	userRep.PhoneNumberToValidate = userKc.GetAttributeString(constants.AttrbPhoneNumberToValidate)
	userRep.Label = userKc.GetAttributeString(constants.AttrbLabel)
	userRep.Gender = userKc.GetAttributeString(constants.AttrbGender)
	userRep.BirthDate = userKc.GetAttributeDate(constants.AttrbBirthDate, constants.SupportedDateLayouts)
	userRep.Locale = userKc.GetAttributeString(constants.AttrbLocale)
	userRep.BusinessID = userKc.GetAttributeString(constants.AttrbBusinessID)
	userRep.NameID = userKc.GetAttributeString(constants.AttrbNameID)
	userRep.OnboardingCompleted, _ = userKc.GetAttributeBool(constants.AttrbOnboardingCompleted)
	userRep.BirthLocation = userKc.GetAttributeString(constants.AttrbBirthLocation)
	userRep.Nationality = userKc.GetAttributeString(constants.AttrbNationality)
	userRep.IDDocumentType = userKc.GetAttributeString(constants.AttrbIDDocumentType)
	userRep.IDDocumentNumber = userKc.GetAttributeString(constants.AttrbIDDocumentNumber)
	userRep.IDDocumentExpiration = userKc.GetAttributeString(constants.AttrbIDDocumentExpiration)
	userRep.IDDocumentCountry = userKc.GetAttributeString(constants.AttrbIDDocumentCountry)

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
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, user.BirthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, user.Nationality)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, user.IDDocumentType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, user.IDDocumentNumber)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, user.IDDocumentExpiration)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, user.IDDocumentCountry)

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	return userRep
}

// MergeUpdatableUserWithoutEmailAndPhoneNumber update a KC user representation from an API user
func MergeUpdatableUserWithoutEmailAndPhoneNumber(target *kc.UserRepresentation, user UpdatableUserRepresentation) {
	// This merge function does not care about contacts (email, phoneNumber)
	target.Username = defaultStringPtr(user.Username, target.Username)
	target.FirstName = defaultStringPtr(user.FirstName, target.FirstName)
	target.LastName = defaultStringPtr(user.LastName, target.LastName)
	target.Enabled = defaultBoolPtr(user.Enabled, target.Enabled)
	target.EmailVerified = defaultBoolPtr(user.EmailVerified, target.EmailVerified)
	if user.Groups != nil {
		target.Groups = user.Groups
	}
	if user.Roles != nil {
		target.RealmRoles = user.Roles
	}

	var attributes = make(kc.Attributes)
	if target.Attributes != nil {
		attributes = *target.Attributes
	}

	attributes.SetBoolWhenNotNil(constants.AttrbPhoneNumberVerified, user.PhoneNumberVerified)
	attributes.SetStringWhenNotNil(constants.AttrbLabel, user.Label)
	attributes.SetStringWhenNotNil(constants.AttrbGender, user.Gender)
	attributes.SetDateWhenNotNil(constants.AttrbBirthDate, user.BirthDate, constants.SupportedDateLayouts)
	attributes.SetStringWhenNotNil(constants.AttrbLocale, user.Locale)
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, user.BirthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, user.Nationality)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, user.IDDocumentType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, user.IDDocumentNumber)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, user.IDDocumentExpiration)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, user.IDDocumentCountry)
	if user.BusinessID.Defined {
		attributes.SetStringWhenNotNil(constants.AttrbBusinessID, user.BusinessID.Value)
	}

	if len(attributes) > 0 {
		target.Attributes = &attributes
	}
}

// ConvertToAPIRole converts a role
func ConvertToAPIRole(role kc.RoleRepresentation) RoleRepresentation {
	var roleRep RoleRepresentation
	roleRep.ID = role.ID
	roleRep.Name = role.Name
	roleRep.Composite = role.Composite
	roleRep.ClientRole = role.ClientRole
	roleRep.ContainerID = role.ContainerID
	roleRep.Description = role.Description
	return roleRep
}

// ConvertToKCRole converts a role
func ConvertToKCRole(role RoleRepresentation) kc.RoleRepresentation {
	return kc.RoleRepresentation{
		ClientRole:  role.ClientRole,
		Composite:   role.Composite,
		ContainerID: role.ContainerID,
		Description: role.Description,
		ID:          role.ID,
		Name:        role.Name,
	}
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

// ConvertToAPIIdentityProvider creates an API IdentityProviderRepresentation from a KC IdentityProviderRepresentation
func ConvertToAPIIdentityProvider(idp kc.IdentityProviderRepresentation) IdentityProviderRepresentation {
	var apiIDP IdentityProviderRepresentation

	apiIDP.AddReadTokenRoleOnCreate = idp.AddReadTokenRoleOnCreate
	apiIDP.Alias = idp.Alias
	apiIDP.AuthenticateByDefault = idp.AuthenticateByDefault
	apiIDP.Config = idp.Config
	apiIDP.DisplayName = idp.DisplayName
	apiIDP.Enabled = idp.Enabled
	apiIDP.FirstBrokerLoginFlowAlias = idp.FirstBrokerLoginFlowAlias
	apiIDP.InternalID = idp.InternalID
	apiIDP.LinkOnly = idp.LinkOnly
	apiIDP.PostBrokerLoginFlowAlias = idp.PostBrokerLoginFlowAlias
	apiIDP.ProviderID = idp.ProviderID
	apiIDP.StoreToken = idp.StoreToken
	apiIDP.TrustEmail = idp.TrustEmail

	return apiIDP
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
		SelfServiceDefaultTab:               config.SelfServiceDefaultTab,
		RedirectCancelledRegistrationURL:    config.RedirectCancelledRegistrationURL,
		RedirectSuccessfulRegistrationURL:   config.RedirectSuccessfulRegistrationURL,
		OnboardingRedirectURI:               config.OnboardingRedirectURI,
		OnboardingClientID:                  config.OnboardingClientID,
		SelfRegisterGroupNames:              defaultStringArray(config.SelfRegisterGroupNames, emptyArray),
		BarcodeType:                         config.BarcodeType,
		AllowedBackURL:                      config.AllowedBackURL,
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
		checks[configuration.CheckKeyIDNow] = false
		checks[configuration.CheckKeyPhysical] = false
		checks[configuration.CheckKeyIDNowAutoIdent] = false
	}
	return RealmAdminConfiguration{
		Mode:                                  defaultString(conf.Mode, "corporate"),
		AvailableChecks:                       checks,
		SelfRegisterEnabled:                   defaultBool(conf.SelfRegisterEnabled, false),
		BoTheme:                               conf.BoTheme,
		SseTheme:                              conf.SseTheme,
		RegisterTheme:                         conf.RegisterTheme,
		SignerTheme:                           conf.SignerTheme,
		NeedVerifiedContact:                   defaultBool(conf.NeedVerifiedContact, true),
		ConsentRequiredSocial:                 defaultBool(conf.ConsentRequiredSocial, false),
		ConsentRequiredCorporate:              defaultBool(conf.ConsentRequiredCorporate, false),
		ShowGlnEditing:                        defaultBool(conf.ShowGlnEditing, false),
		BusinessIDIsNotGLN:                    defaultBool(conf.BusinessIDIsNotGLN, false),
		VideoIdentificationVoucherEnabled:     defaultBool(conf.VideoIdentificationVoucherEnabled, false),
		VideoIdentificationAccountingEnabled:  defaultBool(conf.VideoIdentificationAccountingEnabled, false),
		VideoIdentificationPrepaymentRequired: defaultBool(conf.VideoIdentificationPrepaymentRequired, false),
		AutoIdentificationVoucherEnabled:      defaultBool(conf.AutoIdentificationVoucherEnabled, false),
		AutoIdentificationAccountingEnabled:   defaultBool(conf.AutoIdentificationAccountingEnabled, false),
		AutoIdentificationPrepaymentRequired:  defaultBool(conf.AutoIdentificationPrepaymentRequired, false),
	}
}

// ConvertToDBStruct converts a realm admin configuration into its database version
func (rac RealmAdminConfiguration) ConvertToDBStruct() configuration.RealmAdminConfiguration {
	return configuration.RealmAdminConfiguration{
		Mode:                                  rac.Mode,
		AvailableChecks:                       rac.AvailableChecks,
		SelfRegisterEnabled:                   rac.SelfRegisterEnabled,
		BoTheme:                               rac.BoTheme,
		SseTheme:                              rac.SseTheme,
		RegisterTheme:                         rac.RegisterTheme,
		SignerTheme:                           rac.SignerTheme,
		NeedVerifiedContact:                   rac.NeedVerifiedContact,
		ConsentRequiredSocial:                 rac.ConsentRequiredSocial,
		ConsentRequiredCorporate:              rac.ConsentRequiredCorporate,
		ShowGlnEditing:                        rac.ShowGlnEditing,
		BusinessIDIsNotGLN:                    rac.BusinessIDIsNotGLN,
		VideoIdentificationVoucherEnabled:     rac.VideoIdentificationVoucherEnabled,
		VideoIdentificationAccountingEnabled:  rac.VideoIdentificationAccountingEnabled,
		VideoIdentificationPrepaymentRequired: rac.VideoIdentificationPrepaymentRequired,
		AutoIdentificationVoucherEnabled:      rac.AutoIdentificationVoucherEnabled,
		AutoIdentificationAccountingEnabled:   rac.AutoIdentificationAccountingEnabled,
		AutoIdentificationPrepaymentRequired:  rac.AutoIdentificationPrepaymentRequired,
	}
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

// GetField is used to validate a user against a UserProfile
func (user *UserRepresentation) GetField(field string) interface{} {
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
		return profile.IfNotNil(user.BusinessID)
	default:
		return nil
	}
}

// SetField is used to validate a user against a UserProfile
func (user *UserRepresentation) SetField(field string, value interface{}) {
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
		user.BusinessID = cs.ToStringPtr(value)
		break
	}
}

// Validate is a validator for UserRepresentation
func (user UserRepresentation) Validate(ctx context.Context, upc profile.UserProfile, realm string, checkMandatory bool) error {
	var v = validation.NewParameterValidator().
		ValidateParameterFunc(func() error {
			return profile.Validate(ctx, upc, realm, &user, "management", checkMandatory)
		})
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

// GetField is used to validate a user against a UserProfile
func (user *UpdatableUserRepresentation) GetField(field string) interface{} {
	switch field {
	case fields.Username.Key():
		return profile.IfNotNil(user.Username)
	case fields.Email.Key():
		return toOptionalStringPtr(user.Email)
	case fields.FirstName.Key():
		return profile.IfNotNil(user.FirstName)
	case fields.LastName.Key():
		return profile.IfNotNil(user.LastName)
	case fields.Gender.AttributeName():
		return profile.IfNotNil(user.Gender)
	case fields.PhoneNumber.AttributeName():
		return toOptionalStringPtr(user.PhoneNumber)
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
		return toOptionalStringPtr(user.BusinessID)
	default:
		return nil
	}
}

func toOptionalStringPtr(opt csjson.OptionalString) interface{} {
	if !opt.Defined || opt.Value == nil {
		return nil
	}
	return opt.Value
}

// SetField is used to validate a user against a UserProfile
func (user *UpdatableUserRepresentation) SetField(field string, value interface{}) {
	switch field {
	case fields.Username.Key():
		user.Username = cs.ToStringPtr(value)
		break
	case fields.Email.Key():
		if value == nil {
			user.Email.Defined = false
			user.Email.Value = nil
		} else {
			user.Email.Defined = true
			user.Email.Value = cs.ToStringPtr(value)
		}
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
		if value == nil {
			user.PhoneNumber.Defined = false
			user.PhoneNumber.Value = nil
		} else {
			user.PhoneNumber.Defined = true
			user.PhoneNumber.Value = cs.ToStringPtr(value)
		}
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
		if value == nil {
			user.BusinessID.Defined = false
			user.BusinessID.Value = nil
		} else {
			user.BusinessID.Defined = true
			user.BusinessID.Value = cs.ToStringPtr(value)
		}
		break
	}
}

// Validate is a validator for UpdatableUserRepresentation
func (user UpdatableUserRepresentation) Validate(ctx context.Context, upc profile.UserProfile, realm string) error {
	var v = validation.NewParameterValidator().
		ValidateParameterFunc(func() error {
			return profile.Validate(ctx, upc, realm, &user, "management", false)
		})

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
		ValidateParameterRegExp(constants.Name, role.Name, constants.RegExpName, false).
		ValidateParameterRegExp(constants.Description, role.Description, constants.RegExpRoleDescription, false).
		ValidateParameterRegExp(constants.ContainerID, role.ContainerID, constants.RegExpContainerID, false).
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
		ValidateParameterRegExp(constants.SelfServiceDefaultTab, config.SelfServiceDefaultTab, regExpSseTabName, false).
		ValidateParameterLength(constants.SelfServiceDefaultTab, config.SelfServiceDefaultTab, 1, 20, false).
		ValidateParameterRegExp(constants.RedirectCancelledRegistrationURL, config.RedirectCancelledRegistrationURL, constants.RegExpRedirectURI, false).
		ValidateParameterRegExp(constants.RedirectSuccessfulRegistrationURL, config.RedirectSuccessfulRegistrationURL, constants.RegExpRedirectURI, false).
		ValidateParameterRegExp(constants.OnboardingRedirectURI, config.OnboardingRedirectURI, constants.RegExpRedirectURI, false).
		ValidateParameterRegExp(constants.OnboardingClientID, config.OnboardingClientID, constants.RegExpClientID, false).
		ValidateParameterRegExp(constants.AllowedBackURL, config.AllowedBackURL, constants.RegExpAllowedBackURL, false).
		ValidateParameterIn(constants.BarcodeType, config.BarcodeType, allowedBarcodeType, false).
		Status()
}

// Validate is a validator for RealmAdminConfiguration
func (rac RealmAdminConfiguration) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterIn("mode", rac.Mode, allowedAdminConfMode, true).
		ValidateParameterFunc(rac.validateAvailableChecks).
		ValidateParameterRegExp("botheme", rac.BoTheme, constants.RegExpTheme, false).
		ValidateParameterRegExp("ssetheme", rac.SseTheme, constants.RegExpTheme, false).
		ValidateParameterRegExp("registertheme", rac.RegisterTheme, constants.RegExpTheme, false).
		ValidateParameterRegExp("signertheme", rac.SignerTheme, constants.RegExpTheme, false).
		Status()
}

func (rac RealmAdminConfiguration) validateAvailableChecks() error {
	for k := range rac.AvailableChecks {
		if !validation.IsStringInSlice(configuration.AvailableCheckKeys, k) {
			return errorhandler.CreateBadRequestError(constants.MsgErrInvalidParam + ".available-checks")
		}
	}
	return nil
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
		ValidateParameterRegExp(constants.UserID, fedID.UserID, constants.RegExpFederatedUserID, true).
		ValidateParameterRegExp(constants.Username, fedID.Username, constants.RegExpFederatedUsername, true).
		Status()
}

// ConvertToAPIUserChecks converts user checks from accreditation service struct to API struct
func ConvertToAPIUserChecks(checks []accreditationsclient.CheckRepresentation) []UserCheck {
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
