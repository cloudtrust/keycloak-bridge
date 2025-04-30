package management

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/events"
	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
	"github.com/pkg/errors"
)

const (
	initPasswordAction = "sms-password-set"
	businessRoleFlag   = "BUSINESS_ROLE_FLAG"

	actionVerifyEmail       = "ct-verify-email"
	actionVerifyPhoneNumber = "mobilephone-validation"

	managementOnboardingStatus = "user-created-by-api"
	eventCredentialID          = "credential_id"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	GetRealms(accessToken string) ([]kc.RealmRepresentation, error)
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetRequiredActions(accessToken string, realmName string) ([]kc.RequiredActionProviderRepresentation, error)
	GetClient(accessToken string, realmName, idClient string) (kc.ClientRepresentation, error)
	GetClients(accessToken string, realmName string, paramKV ...string) ([]kc.ClientRepresentation, error)
	DeleteUser(accessToken string, realmName, userID string) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
	AddGroupToUser(accessToken string, realmName, userID, groupID string) error
	DeleteGroupFromUser(accessToken string, realmName, userID, groupID string) error
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation, paramKV ...string) (string, error)
	GetClientRoleMappings(accessToken string, realmName, userID, clientID string) ([]kc.RoleRepresentation, error)
	AddClientRolesToUserRoleMapping(accessToken string, realmName, userID, clientID string, roles []kc.RoleRepresentation) error
	DeleteClientRolesFromUserRoleMapping(accessToken string, realmName, userID, clientID string, roles []kc.RoleRepresentation) error
	GetRealmLevelRoleMappings(accessToken string, realmName, userID string) ([]kc.RoleRepresentation, error)
	AddRealmLevelRoleMappings(accessToken string, realmName, userID string, roles []kc.RoleRepresentation) error
	DeleteRealmLevelRoleMappings(accessToken string, realmName, userID string, roles []kc.RoleRepresentation) error
	ResetPassword(accessToken string, realmName string, userID string, cred kc.CredentialRepresentation) error
	ExecuteActionsEmail(accessToken string, reqRealmName string, targetRealmName string, userID string, actions []string, paramKV ...string) error
	SendSmsCode(accessToken string, realmName string, userID string) (kc.SmsCodeRepresentation, error)
	CreateRecoveryCode(accessToken string, realmName string, userID string) (kc.RecoveryCodeRepresentation, error)
	CreateActivationCode(accessToken string, realmName string, userID string) (kc.ActivationCodeRepresentation, error)
	SendReminderEmail(accessToken string, realmName string, userID string, paramKV ...string) error
	GetRoles(accessToken string, realmName string) ([]kc.RoleRepresentation, error)
	GetRolesWithAttributes(accessToken string, realmName string) ([]kc.RoleRepresentation, error)
	GetRole(accessToken string, realmName string, roleID string) (kc.RoleRepresentation, error)
	CreateRole(accessToken string, realmName string, role kc.RoleRepresentation) (string, error)
	UpdateRole(accessToken string, realmName string, roleID string, role kc.RoleRepresentation) error
	DeleteRole(accessToken string, realmName string, roleID string) error
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	GetClientRoles(accessToken string, realmName, idClient string) ([]kc.RoleRepresentation, error)
	CreateClientRole(accessToken string, realmName, clientID string, role kc.RoleRepresentation) (string, error)
	GetGroup(accessToken string, realmName, groupID string) (kc.GroupRepresentation, error)
	CreateGroup(accessToken string, realmName string, group kc.GroupRepresentation) (string, error)
	DeleteGroup(accessToken string, realmName string, groupID string) error
	AssignClientRole(accessToken string, realmName string, groupID string, clientID string, role []kc.RoleRepresentation) error
	RemoveClientRole(accessToken string, realmName string, groupID string, clientID string, role []kc.RoleRepresentation) error
	GetGroupClientRoles(accessToken string, realmName string, groupID string, clientID string) ([]kc.RoleRepresentation, error)
	GetAvailableGroupClientRoles(accessToken string, realmName string, groupID string, clientID string) ([]kc.RoleRepresentation, error)
	GetCredentials(accessToken string, realmName string, userID string) ([]kc.CredentialRepresentation, error)
	UpdateLabelCredential(accessToken string, realmName string, userID string, credentialID string, label string) error
	DeleteCredential(accessToken string, realmName string, userID string, credentialID string) error
	ResetPapercardFailures(accessToken string, realmName string, userID string, credentialID string) error
	GetFederatedIdentities(accessToken string, realmName string, userID string) ([]kc.FederatedIdentityRepresentation, error)
	LinkShadowUser(accessToken string, realmName string, userID string, provider string, fedID kc.FederatedIdentityRepresentation) error
	ClearUserLoginFailures(accessToken string, realmName, userID string) error
	GetAttackDetectionStatus(accessToken string, realmName, userID string) (map[string]interface{}, error)
	GetIdps(accessToken string, realmName string) ([]kc.IdentityProviderRepresentation, error)
}

// AccreditationsServiceClient interface
type AccreditationsServiceClient interface {
	GetChecks(ctx context.Context, realm string, userID string) ([]accreditationsclient.CheckRepresentation, error)
	GetPendingChecks(ctx context.Context, realm string, userID string) ([]accreditationsclient.CheckRepresentation, error)
	NotifyUpdate(ctx context.Context, updateNotifyRequest accreditationsclient.UpdateNotificationRepresentation) ([]string, error)
}

// OnboardingModule is the interface for the onboarding process
type OnboardingModule interface {
	OnboardingAlreadyCompleted(kc.UserRepresentation) (bool, error)
	SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, username string, onboardingClientID string,
		onboardingRedirectURI string, themeRealmName string, reminder bool, paramKV ...string) error
	CreateUser(ctx context.Context, accessToken, realmName, targetRealmName string, kcUser *kc.UserRepresentation, generateNameID bool) (string, error)
	ProcessAlreadyExistingUserCases(ctx context.Context, accessToken string, targetRealmName string, userEmail string, requestingSource string, handler func(username string, createdTimestamp int64, thirdParty *string) error) error
	ComputeOnboardingRedirectURI(ctx context.Context, targetRealmName string, customerRealmName string, realmConf configuration.RealmConfiguration) (string, error)
}

// AuthorizationChecker interface
type AuthorizationChecker interface {
	CheckAuthorizationForGroupsOnTargetRealm(realm string, groups []string, action, targetRealm string) error
	CheckAuthorizationForGroupsOnTargetGroup(realm string, groups []string, action, targetRealm, targetGroup string) error
	ReloadAuthorizations(ctx context.Context) error
}

// UserProfileCache interface
type UserProfileCache interface {
	GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error)
}

// Component is the management component interface.
type Component interface {
	GetActions(ctx context.Context) ([]api.ActionRepresentation, error)

	GetRealms(ctx context.Context) ([]api.RealmRepresentation, error)
	GetRealm(ctx context.Context, realmName string) (api.RealmRepresentation, error)
	GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error)
	GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error)
	GetRequiredActions(ctx context.Context, realmName string) ([]api.RequiredActionRepresentation, error)

	DeleteUser(ctx context.Context, realmName, userID string) error
	GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error)
	UpdateUser(ctx context.Context, realmName, userID string, user api.UpdatableUserRepresentation) error
	LockUser(ctx context.Context, realmName, userID string) error
	UnlockUser(ctx context.Context, realmName, userID string) error
	GetUsers(ctx context.Context, realmName string, groupIDs []string, paramKV ...string) (api.UsersPageRepresentation, error)
	CreateUser(ctx context.Context, realmName string, user api.UserRepresentation, generateUsername bool, generateNameID bool, termsOfUse bool) (string, error)
	CreateUserInSocialRealm(ctx context.Context, user api.UserRepresentation, generateNameID bool) (string, error)
	GetUserChecks(ctx context.Context, realmName, userID string) ([]api.UserCheck, error)
	GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error)
	GetUserAccountStatusByEmail(ctx context.Context, realmName, email string) (api.UserStatus, error)
	GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error)
	AddRoleToUser(ctx context.Context, realmName, userID string, roleID string) error
	DeleteRoleForUser(ctx context.Context, realmName, userID string, roleID string) error
	GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error)
	AddGroupToUser(ctx context.Context, realmName, userID string, groupID string) error
	DeleteGroupForUser(ctx context.Context, realmName, userID string, groupID string) error
	GetAvailableTrustIDGroups(ctx context.Context, realmName string) ([]string, error)
	GetTrustIDGroupsOfUser(ctx context.Context, realmName, userID string) ([]string, error)
	SetTrustIDGroupsToUser(ctx context.Context, realmName, userID string, groupNames []string) error
	GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error)
	AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error
	DeleteClientRolesFromUser(ctx context.Context, realmName, userID, clientID string, roleID string, roleName string) error

	ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) (string, error)
	ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []api.RequiredAction, paramKV ...string) error
	RevokeAccreditations(ctx context.Context, realmName string, userID string) error
	SendSmsCode(ctx context.Context, realmName string, userID string) (string, error)
	SendOnboardingEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, paramKV ...string) error
	SendOnboardingEmailInSocialRealm(ctx context.Context, userID string, customerRealm string, reminder bool, paramKV ...string) error
	/* REMOVE_THIS_3901 : start */
	SendMigrationEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, lifespan *int) error
	/* REMOVE_THIS_3901 : end */
	SendReminderEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error
	ResetSmsCounter(ctx context.Context, realmName string, userID string) error
	CreateRecoveryCode(ctx context.Context, realmName string, userID string) (string, error)
	CreateActivationCode(ctx context.Context, realmName string, userID string) (string, error)
	GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error)
	DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error
	ResetCredentialFailuresForUser(ctx context.Context, realmName string, userID string, credentialID string) error
	ClearUserLoginFailures(ctx context.Context, realmName, userID string) error
	GetAttackDetectionStatus(ctx context.Context, realmName, userID string) (api.AttackDetectionStatusRepresentation, error)
	GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error)
	GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error)
	CreateRole(ctx context.Context, realmName string, role api.RoleRepresentation) (string, error)
	UpdateRole(ctx context.Context, realmName string, roleID string, role api.RoleRepresentation) error
	DeleteRole(ctx context.Context, realmName string, roleID string) error
	GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error)
	CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error)
	DeleteClientRole(ctx context.Context, realmName, clientID string, roleID string) error

	GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error)
	CreateGroup(ctx context.Context, realmName string, group api.GroupRepresentation) (string, error)
	DeleteGroup(ctx context.Context, realmName string, groupID string) error
	GetAuthorizations(ctx context.Context, realmName string, groupID string) (api.AuthorizationsRepresentation, error)
	UpdateAuthorizations(ctx context.Context, realmName string, groupID string, group api.AuthorizationsRepresentation) error
	AddAuthorization(ctx context.Context, realmName string, groupID string, group api.AuthorizationsRepresentation) error
	GetAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) (api.AuthorizationMessage, error)
	DeleteAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) error

	GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error)
	UpdateRealmCustomConfiguration(ctx context.Context, realmID string, customConfig api.RealmCustomConfiguration) error
	GetRealmAdminConfiguration(ctx context.Context, realmName string) (api.RealmAdminConfiguration, error)
	UpdateRealmAdminConfiguration(ctx context.Context, realmID string, adminConfig api.RealmAdminConfiguration) error
	GetRealmUserProfile(ctx context.Context, realmID string) (apicommon.ProfileRepresentation, error)
	GetRealmBackOfficeConfiguration(ctx context.Context, realmID string, groupName string) (api.BackOfficeConfiguration, error)
	UpdateRealmBackOfficeConfiguration(ctx context.Context, realmID string, groupName string, config api.BackOfficeConfiguration) error
	GetUserRealmBackOfficeConfiguration(ctx context.Context, realmID string) (api.BackOfficeConfiguration, error)

	GetFederatedIdentities(ctx context.Context, realmName string, userID string) ([]api.FederatedIdentityRepresentation, error)
	LinkShadowUser(ctx context.Context, realmName string, userID string, provider string, fedID api.FederatedIdentityRepresentation) error

	GetIdentityProviders(ctx context.Context, realmName string) ([]api.IdentityProviderRepresentation, error)
}

// EventsReporterModule is the interface of the audit events module
type EventsReporterModule interface {
	ReportEvent(ctx context.Context, event events.Event)
}

// KafkaProducer interface
type KafkaProducer interface {
	SendMessageBytes(value []byte) error
}

// Component is the management component.
type component struct {
	keycloakClient            KeycloakClient
	kcURIProvider             KeycloakURIProvider /* REMOVE_THIS_3901 */
	profileCache              UserProfileCache
	auditEventsReporterModule EventsReporterModule
	configDBModule            keycloakb.ConfigurationDBModule
	onboardingModule          OnboardingModule
	authChecker               AuthorizationChecker
	tokenProvider             toolbox.OidcTokenProvider
	authorizedTrustIDGroups   map[string]bool
	socialRealmName           string
	accreditationsClient      AccreditationsServiceClient
	logger                    log.Logger
	originEvent               string
	kafkaAuthReloadProducer   KafkaProducer
}

// NewComponent returns the management component.
func NewComponent(keycloakClient KeycloakClient, kcURIProvider kc.KeycloakURIProvider, profileCache UserProfileCache, auditEventsReporterModule EventsReporterModule,
	configDBModule keycloakb.ConfigurationDBModule, onboardingModule OnboardingModule, authChecker AuthorizationChecker, tokenProvider toolbox.OidcTokenProvider,
	accreditationsClient AccreditationsServiceClient, authorizedTrustIDGroups []string, socialRealmName string, logger log.Logger, kafkaAuthReloadProducer KafkaProducer) Component {
	/* REMOVE_THIS_3901 : remove second provided parameter */

	var authzedTrustIDGroups = make(map[string]bool)
	for _, grp := range authorizedTrustIDGroups {
		authzedTrustIDGroups[grp] = true
	}

	return &component{
		keycloakClient:            keycloakClient,
		kcURIProvider:             kcURIProvider, /* REMOVE_THIS_3901 */
		profileCache:              profileCache,
		auditEventsReporterModule: auditEventsReporterModule,
		configDBModule:            configDBModule,
		onboardingModule:          onboardingModule,
		authChecker:               authChecker,
		tokenProvider:             tokenProvider,
		authorizedTrustIDGroups:   authzedTrustIDGroups,
		socialRealmName:           socialRealmName,
		accreditationsClient:      accreditationsClient,
		logger:                    logger,
		originEvent:               "back-office",
		kafkaAuthReloadProducer:   kafkaAuthReloadProducer,
	}
}

func (c *component) GetRealms(ctx context.Context) ([]api.RealmRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	realmsKc, err := c.keycloakClient.GetRealms(accessToken)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var realmsRep = []api.RealmRepresentation{}
	for _, realmKc := range realmsKc {
		var realmRep api.RealmRepresentation
		realmRep.ID = realmKc.ID
		realmRep.KeycloakVersion = realmKc.KeycloakVersion
		realmRep.Realm = realmKc.Realm
		realmRep.DisplayName = realmKc.DisplayName
		realmRep.Enabled = realmKc.Enabled
		realmsRep = append(realmsRep, realmRep)
	}

	return realmsRep, err

}

func (c *component) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var realmRep api.RealmRepresentation
	realmKc, err := c.keycloakClient.GetRealm(accessToken, realm)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.RealmRepresentation{}, err
	}

	realmRep.ID = realmKc.ID
	realmRep.KeycloakVersion = realmKc.KeycloakVersion
	realmRep.Realm = realmKc.Realm
	realmRep.DisplayName = realmKc.DisplayName
	realmRep.Enabled = realmKc.Enabled

	return realmRep, nil
}

func (c *component) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var clientRep api.ClientRepresentation
	clientKc, err := c.keycloakClient.GetClient(accessToken, realmName, idClient)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.ClientRepresentation{}, err
	}

	clientRep.ID = clientKc.ID
	clientRep.Name = clientKc.Name
	clientRep.BaseURL = clientKc.BaseURL
	clientRep.ClientID = clientKc.ClientID
	clientRep.Protocol = clientKc.Protocol
	clientRep.Enabled = clientKc.Enabled

	return clientRep, nil
}

func (c *component) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	clientsKc, err := c.keycloakClient.GetClients(accessToken, realmName)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var clientsRep = []api.ClientRepresentation{}
	for _, clientKc := range clientsKc {
		var clientRep api.ClientRepresentation
		clientRep.ID = clientKc.ID
		clientRep.Name = clientKc.Name
		clientRep.BaseURL = clientKc.BaseURL
		clientRep.ClientID = clientKc.ClientID
		clientRep.Protocol = clientKc.Protocol
		clientRep.Enabled = clientKc.Enabled
		clientsRep = append(clientsRep, clientRep)
	}

	return clientsRep, nil
}

func (c *component) GetRequiredActions(ctx context.Context, realmName string) ([]api.RequiredActionRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	requiredActionsKc, err := c.keycloakClient.GetRequiredActions(accessToken, realmName)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var requiredActionsRep = []api.RequiredActionRepresentation{}
	for _, requiredActionKc := range requiredActionsKc {
		if *requiredActionKc.Enabled {
			var requiredActionRep = api.ConvertRequiredAction(&requiredActionKc)
			requiredActionsRep = append(requiredActionsRep, requiredActionRep)
		}
	}

	return requiredActionsRep, nil
}

func (c *component) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation, generateUsername bool, generateNameID bool, termsOfUse bool) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)
	return c.genericCreateUser(ctx, accessToken, ctxRealm, realmName, "api", user, generateUsername, generateNameID, termsOfUse, false)
}

func (c *component) CreateUserInSocialRealm(ctx context.Context, user api.UserRepresentation, generateNameID bool) (string, error) {
	var accessToken, err = c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Info(ctx, "msg", "Fails to get OIDC token from keycloak", "err", err.Error())
		return "", err
	}

	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)
	var realmName = c.socialRealmName
	return c.genericCreateUser(ctx, accessToken, ctxRealm, realmName, ctxRealm, user, true, generateNameID, true, true)
}

func (c *component) genericCreateUser(ctx context.Context, accessToken string, customerRealmName string, targetRealmName string, source string,
	user api.UserRepresentation, generateUsername bool, generateNameID bool, termsOfUse bool, useOnboardingCheckForExistingUser bool) (string, error) {
	var userRep = api.ConvertToKCUser(user)
	userRep.SetAttributeString(constants.AttrbSource, source)

	realmAdminConfig, err := c.configDBModule.GetAdminConfiguration(ctx, targetRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to retrieve realm admin configuration", "err", err.Error())
		return "", err
	}

	if realmAdminConfig.OnboardingStatusEnabled != nil && *realmAdminConfig.OnboardingStatusEnabled {
		userRep.SetAttributeString(constants.AttrbOnboardingStatus, managementOnboardingStatus)
	}

	if termsOfUse {
		var reqActions []string
		if userRep.RequiredActions != nil {
			reqActions = *userRep.RequiredActions
		}
		reqActions = append(reqActions, "ct-terms-of-use")
		userRep.RequiredActions = &reqActions
	}

	var locationURL string
	if targetRealmName == c.socialRealmName || generateUsername {
		if useOnboardingCheckForExistingUser {
			err = c.onboardingModule.ProcessAlreadyExistingUserCases(ctx, accessToken, targetRealmName, *user.Email, customerRealmName, c.onAlreadyExistsUser)
			if err != nil {
				c.logger.Warn(ctx, "msg", "Can't process already existing user cases", "err", err.Error())
				return "", err
			}
		}
		// Ignore username and create a random one
		userRep.Username = nil
		locationURL, err = c.onboardingModule.CreateUser(ctx, accessToken, customerRealmName, targetRealmName, &userRep, generateNameID)
	} else {
		// Store user in KC
		locationURL, err = c.keycloakClient.CreateUser(accessToken, customerRealmName, targetRealmName, userRep, "generateNameID", strconv.FormatBool(generateNameID))
	}
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	var username = ""
	if userRep.Username != nil {
		username = *userRep.Username
	}

	//retrieve the user ID
	reg := regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)
	userID := string(reg.Find([]byte(locationURL)))

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "API_ACCOUNT_CREATION", targetRealmName, userID, username, nil))

	return locationURL, nil
}

// this function is called by onboardingModule.ProcessAlreadyExistingUserCases when an account already exists for a given email
// register interface sends an email to the user... In management, we only return an error
func (c *component) onAlreadyExistsUser(_ string, _ int64, _ *string) error {
	return errorhandler.Error{
		Status:  http.StatusConflict,
		Message: "keycloak.existing.username",
	}
}

func (c *component) DeleteUser(ctx context.Context, realmName, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	err := c.keycloakClient.DeleteUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "API_ACCOUNT_DELETION", realmName, userID, events.CtEventUnknownUsername, nil))

	return nil
}

func (c *component) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var userRep api.UserRepresentation
	userKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return userRep, err
	}
	keycloakb.ConvertLegacyAttribute(&userKc)

	userRep = api.ConvertToAPIUser(ctx, userKc, c.logger)

	var username = ""
	if userKc.Username != nil {
		username = *userKc.Username
	}

	pendingChecks, err := c.accreditationsClient.GetPendingChecks(ctx, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get pending checks", "err", err.Error())
		return userRep, err
	}
	userRep.PendingChecks = keycloakb.ConvertFromAccreditationChecks(pendingChecks).ToCheckNames()

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "GET_DETAILS", realmName, userID, username, nil))

	return userRep, nil
}

func isEmailVerified(user kc.UserRepresentation) bool {
	return user.EmailVerified != nil && *user.EmailVerified
}

func isPhoneNumberVerified(user kc.UserRepresentation) bool {
	var value, err = user.GetAttributeBool(constants.AttrbPhoneNumberVerified)
	return err == nil && value != nil && *value
}

func (c *component) UpdateUser(ctx context.Context, realmName, userID string, user api.UpdatableUserRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var removeAttributes []kc.AttributeKey

	// get the "old" user representation
	oldUserKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&oldUserKc)

	if realmName == c.socialRealmName {
		// Self register enabled: we can't update the username
		user.Username = oldUserKc.Username
	}

	var fieldsComparator = fields.NewFieldsComparator().
		CompareValueAndFunctionForUpdate(fields.Gender, user.Gender, oldUserKc.GetFieldValues).
		CompareOptionalAndFunction(fields.Email, user.Email, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.FirstName, user.FirstName, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.LastName, user.LastName, oldUserKc.GetFieldValues).
		CompareOptionalAndFunction(fields.BusinessID, user.BusinessID, oldUserKc.GetFieldValues).
		CompareOptionalAndFunction(fields.PhoneNumber, user.PhoneNumber, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.BirthDate, user.BirthDate, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.BirthLocation, user.BirthLocation, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.Nationality, user.Nationality, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentType, user.IDDocumentType, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentNumber, user.IDDocumentNumber, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentExpiration, user.IDDocumentExpiration, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentCountry, user.IDDocumentCountry, oldUserKc.GetFieldValues)

	var actions []api.RequiredAction

	// when the email changes, set the EmailVerified to false
	if user.Email.Defined {
		if user.Email.Value == nil {
			var verified = false
			user.EmailVerified = &verified
			removeAttributes = append(removeAttributes, constants.AttrbEmailToValidate)
		} else if fieldsComparator.IsAnyFieldUpdated(fields.Email) {
			if isEmailVerified(oldUserKc) {
				oldUserKc.SetAttributeString(constants.AttrbEmailToValidate, *user.Email.Value)
			} else {
				oldUserKc.Email = user.Email.Value
				oldUserKc.RemoveAttribute(constants.AttrbEmailToValidate)
			}
			actions = append(actions, actionVerifyEmail)
		}
	}

	// when the phone number changes, set the PhoneNumberVerified to false
	if user.PhoneNumber.Defined {
		if user.PhoneNumber.Value == nil {
			removeAttributes = append(removeAttributes, constants.AttrbPhoneNumber, constants.AttrbPhoneNumberVerified, constants.AttrbPhoneNumberToValidate)
		} else if fieldsComparator.IsAnyFieldUpdated(fields.PhoneNumber) {
			if isPhoneNumberVerified(oldUserKc) {
				oldUserKc.SetAttributeString(constants.AttrbPhoneNumberToValidate, *user.PhoneNumber.Value)
			} else {
				oldUserKc.SetAttributeString(constants.AttrbPhoneNumber, *user.PhoneNumber.Value)
				oldUserKc.RemoveAttribute(constants.AttrbPhoneNumberToValidate)
			}
			if len(oldUserKc.GetFieldValues(fields.PhoneNumber)) > 0 {
				actions = append(actions, actionVerifyPhoneNumber)
			}
		}
	}

	var updateRequest = accreditationsclient.UpdateNotificationRepresentation{
		UserID:        &userID,
		RealmName:     &realmName,
		UpdatedFields: fieldsComparator.UpdatedFields(),
	}
	revokeAccreds, err := c.accreditationsClient.NotifyUpdate(ctx, updateRequest)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to notify accreditation service", "err", err.Error())
		return err
	}
	var ap, _ = keycloakb.NewAccreditationsProcessor(oldUserKc.GetFieldValues(fields.Accreditations))
	ap.RevokeTypes(revokeAccreds, func(accred keycloakb.AccreditationRepresentation) {
		c.reportAccreditationRevokedEvent(ctx, realmName, userID, *user.Username, accred)
	})
	newAccreditations := ap.ToKeycloak()

	var oldEnabled = oldUserKc.Enabled
	api.MergeUpdatableUserWithoutEmailAndPhoneNumber(&oldUserKc, user)
	if user.Email.Defined && user.Email.Value == nil {
		// empty string to remove an email
		oldUserKc.Email = user.Email.ToValue("")
	}

	// Remove some attributes
	if oldUserKc.Attributes != nil {
		for _, key := range removeAttributes {
			delete(*oldUserKc.Attributes, key)
		}
	}

	if len(newAccreditations) > 0 {
		oldUserKc.SetFieldValues(fields.Accreditations, newAccreditations)
	}

	// Update in KC
	if err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, oldUserKc); err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB in case where user.Enable is present
	if user.Enabled != nil && (oldEnabled == nil || *user.Enabled != *oldEnabled) {
		c.reportLockEvent(ctx, realmName, userID, user.Username, *user.Enabled)
	}

	if len(actions) > 0 && (isEmailVerified(oldUserKc) || isPhoneNumberVerified(oldUserKc)) {
		// Don't send actions email if account has never been verified. In this case, actions will be part of the onboarding
		// Consider account has never configured if email and phone number are not verified
		var err = c.ExecuteActionsEmail(ctx, realmName, userID, actions)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't execute actions", "err", err.Error(), "actions", actions)
		}
	}

	return nil
}

func (c *component) reportAccreditationRevokedEvent(ctx context.Context, realmName string, userID string, username string, accred keycloakb.AccreditationRepresentation) {
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "ACCREDITATION_REVOKED", realmName, userID, username, accred.ToDetails()))
}

func (c *component) reportLockEvent(ctx context.Context, realmName, userID string, username *string, enabled bool) {
	var blank = ""
	if username == nil {
		username = &blank
	}

	//add ct_event_type
	var ctEventType string
	if enabled {
		// UNLOCK_ACCOUNT ct_event_type
		ctEventType = "UNLOCK_ACCOUNT"
	} else {
		// LOCK_ACCOUNT ct_event_type
		ctEventType = "LOCK_ACCOUNT"
	}

	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, ctEventType, realmName, userID, *username, nil))
}

func (c *component) LockUser(ctx context.Context, realmName, userID string) error {
	return c.setUserLock(ctx, realmName, userID, true)
}

func (c *component) UnlockUser(ctx context.Context, realmName, userID string) error {
	return c.setUserLock(ctx, realmName, userID, false)
}

func (c *component) setUserLock(ctx context.Context, realmName, userID string, locked bool) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the "old" user representation
	oldUserKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&oldUserKc)

	var enabled = !locked
	if oldUserKc.Enabled != nil && *oldUserKc.Enabled == enabled {
		return nil
	}
	oldUserKc.Enabled = &enabled

	// Update in KC
	if err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, oldUserKc); err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	c.reportLockEvent(ctx, realmName, userID, oldUserKc.Username, enabled)

	return nil
}

func (c *component) GetUsers(ctx context.Context, realmName string, groupIDs []string, paramKV ...string) (api.UsersPageRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	for _, groupID := range groupIDs {
		paramKV = append(paramKV, "groupId", groupID)
	}

	usersKc, err := c.keycloakClient.GetUsers(accessToken, ctxRealm, realmName, paramKV...)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UsersPageRepresentation{}, err
	}

	for i := 0; i < len(usersKc.Users); i++ {
		keycloakb.ConvertLegacyAttribute(&usersKc.Users[i])
	}
	return api.ConvertToAPIUsersPage(ctx, usersKc, c.logger), nil
}

func (c *component) GetUserChecks(ctx context.Context, realmName, userID string) ([]api.UserCheck, error) {
	// We can assume userID is valid as it is used to check authorizations...
	var checks, err = c.accreditationsClient.GetChecks(ctx, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user checks", "err", err.Error(), "realm", realmName, "user", userID)
		return nil, err
	}
	return api.ConvertToAPIUserChecks(checks), nil
}

// GetUserAccountStatus gets the user status : user should be enabled in Keycloak and have multifactor activated
func (c *component) GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var res = map[string]bool{"enabled": false}

	userKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	// Here, we don't call keycloakb.ConvertLegacyAttribute as attributes are not used

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return res, err
	}

	if !*userKc.Enabled {
		return res, nil
	}

	creds, err := c.GetCredentialsForUser(ctx, realmName, userID)
	res["enabled"] = len(creds) > 1
	return res, err
}

func (c *component) getUniqueUserByEmail(ctx context.Context, realmName, email string) (kc.UserRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	var users, err = c.keycloakClient.GetUsers(accessToken, ctxRealm, realmName, "email", "="+email)
	if err != nil {
		c.logger.Warn(ctx, "err", "Can't get user by email", "realm", realmName)
		return kc.UserRepresentation{}, err
	}
	// Only search in first page
	if len(users.Users) == 0 {
		return kc.UserRepresentation{}, errorhandler.CreateNotFoundError(prmQryEmail)
	}

	if len(users.Users) > 1 {
		c.logger.Warn(ctx, "err", "Too many users found by email", "realm", realmName)
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("tooManyRows")
	}

	return users.Users[0], nil
}

// GetUserAccountStatusByEmail gets the user onboarding status based on the email
func (c *component) GetUserAccountStatusByEmail(ctx context.Context, realmName, email string) (api.UserStatus, error) {
	var user, err = c.getUniqueUserByEmail(ctx, realmName, email)

	if err != nil {
		return api.UserStatus{}, err
	}

	var numberOfCredentials *int
	if creds, err := c.GetCredentialsForUser(ctx, realmName, *user.ID); err == nil {
		var number = len(creds)
		numberOfCredentials = &number
	} else {
		c.logger.Warn(ctx, "err", "Can't get user credentials", "realm", realmName, "id", user.ID)
		return api.UserStatus{}, err
	}

	var phoneNumberVerified, _ = user.GetAttributeBool(constants.AttrbPhoneNumberVerified)
	var onboardingCompleted, _ = c.onboardingModule.OnboardingAlreadyCompleted(user)

	return api.UserStatus{
		Email:               user.Email,
		Enabled:             user.Enabled,
		EmailVerified:       user.EmailVerified,
		PhoneNumberVerified: phoneNumberVerified,
		OnboardingCompleted: &onboardingCompleted,
		NumberOfCredentials: numberOfCredentials,
	}, nil
}

func (c *component) GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetRealmLevelRoleMappings(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}
	userRoles, err := c.getRolesWithAttributes(accessToken, realmName, rolesKc)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get user roles", "realm", realmName, "user")
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range userRoles {
		if c.isBusinessRole(roleKc) {
			rolesRep = append(rolesRep, api.ConvertToAPIRole(roleKc))
		}
	}

	return rolesRep, nil
}

func (c *component) rolesToMap(roles []kc.RoleRepresentation) map[string]kc.RoleRepresentation {
	var res = make(map[string]kc.RoleRepresentation)
	for _, role := range roles {
		if c.isBusinessRole(role) {
			res[*role.ID] = role
		}
	}
	return res
}

func (c *component) getRolesAsMap(ctx context.Context, realmName string) (map[string]kc.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var roles, err = c.keycloakClient.GetRolesWithAttributes(accessToken, realmName)
	if err != nil {
		c.logger.Info(ctx, "msg", "Failed to get realm role mappings", "realm", realmName, "user")
		return nil, err
	}
	return c.rolesToMap(roles), nil
}

func (c *component) getUserRolesAsMap(ctx context.Context, realmName, userID string) (map[string]kc.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var roles, err = c.keycloakClient.GetRealmLevelRoleMappings(accessToken, realmName, userID)
	if err != nil {
		c.logger.Info(ctx, "msg", "Failed to get user roles", "realm", realmName, "user")
		return nil, err
	}
	userRoles, err := c.getRolesWithAttributes(accessToken, realmName, roles)
	if err != nil {
		c.logger.Info(ctx, "msg", "Failed to get user roles", "realm", realmName, "user")
		return nil, err
	}

	return c.rolesToMap(userRoles), nil
}

func (c *component) getRolesWithAttributes(accessToken string, realmName string, roles []kc.RoleRepresentation) ([]kc.RoleRepresentation, error) {
	var userRoles []kc.RoleRepresentation
	for _, role := range roles {
		userRole, err := c.keycloakClient.GetRole(accessToken, realmName, *role.ID)
		if err != nil {
			return []kc.RoleRepresentation{}, err
		}
		userRoles = append(userRoles, userRole)
	}
	return userRoles, nil
}

func (c *component) AddRoleToUser(ctx context.Context, realmName, userID, roleID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var rolesMap, err = c.getRolesAsMap(ctx, realmName)
	if err != nil {
		return err
	}
	var roles []kc.RoleRepresentation
	if role, ok := rolesMap[roleID]; ok {
		roles = append(roles, role)
	}
	if len(roles) == 0 {
		c.logger.Info(ctx, "msg", "Unknown role", "realm", realmName, "user", userID, "role", roleID)
		return errorhandler.CreateBadRequestError("role")
	}
	err = c.keycloakClient.AddRealmLevelRoleMappings(accessToken, realmName, userID, roles)
	if err != nil {
		c.logger.Info(ctx, "msg", "Failed to add user roles", "user", userID, "role", roleID)
	}
	return err
}

func (c *component) DeleteRoleForUser(ctx context.Context, realmName, userID, roleID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var rolesMap, err = c.getUserRolesAsMap(ctx, realmName, userID)
	if err != nil {
		return err
	}
	var roles []kc.RoleRepresentation
	if role, ok := rolesMap[roleID]; ok {
		roles = append(roles, role)
	}
	if len(roles) == 0 {
		c.logger.Info(ctx, "msg", "Unknown role", "realm", realmName, "user", userID, "role", roleID)
		return errorhandler.CreateBadRequestError("role")
	}
	err = c.keycloakClient.DeleteRealmLevelRoleMappings(accessToken, realmName, userID, roles)
	if err != nil {
		c.logger.Info(ctx, "msg", "Failed to delete user roles", "user", userID, "role", roleID)
	}
	return err
}

func (c *component) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	groupsKc, err := c.keycloakClient.GetGroupsOfUser(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var groupsRep = []api.GroupRepresentation{}
	for _, groupKc := range groupsKc {
		var groupRep api.GroupRepresentation
		groupRep.ID = groupKc.ID
		groupRep.Name = groupKc.Name

		groupsRep = append(groupsRep, groupRep)
	}

	return groupsRep, nil
}

func (c *component) AddGroupToUser(ctx context.Context, realmName, userID string, groupID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	return c.keycloakClient.AddGroupToUser(accessToken, realmName, userID, groupID)
}

func (c *component) DeleteGroupForUser(ctx context.Context, realmName, userID string, groupID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	return c.keycloakClient.DeleteGroupFromUser(accessToken, realmName, userID, groupID)
}

func (c *component) GetAvailableTrustIDGroups(ctx context.Context, realmName string) ([]string, error) {
	var res []string
	for key := range c.authorizedTrustIDGroups {
		res = append(res, key)
	}
	return res, nil
}

func (c *component) GetTrustIDGroupsOfUser(ctx context.Context, realmName, userID string) ([]string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentUser, err = c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}
	var groups = make([]string, 0)
	for _, grp := range currentUser.GetAttribute(constants.AttrbTrustIDGroups) {
		grp = strings.TrimPrefix(grp, "/")
		groups = append(groups, grp)
	}

	return groups, nil
}

func (c *component) SetTrustIDGroupsToUser(ctx context.Context, realmName, userID string, groupNames []string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// validate the input - trustID groups must be valid
	var extGroupNames []string
	for _, groupName := range groupNames {
		if _, ok := c.authorizedTrustIDGroups[groupName]; ok {
			extGroupNames = append(extGroupNames, "/"+groupName)
		} else {
			// unauthorized call (unknown trustID group) --> error
			c.logger.Warn(ctx, "msg", groupName+" group is not allowed to be set as a trustID group")
			return errorhandler.CreateBadRequestError(constants.MsgErrInvalidParam + "." + constants.TrustIDGroupName)
		}
	}

	// get the "old" user representation
	currentUser, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&currentUser)

	// set the trustID groups attributes
	if currentUser.Attributes == nil {
		var emptyMap = make(kc.Attributes)
		currentUser.Attributes = &emptyMap
	}
	(*currentUser.Attributes)[constants.AttrbTrustIDGroups] = extGroupNames

	err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, currentUser)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}

func (c *component) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetClientRoleMappings(accessToken, realmName, userID, clientID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.ID = roleKc.ID
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerID = roleKc.ContainerID
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var rolesRep = []kc.RoleRepresentation{}
	for _, role := range roles {
		rolesRep = append(rolesRep, api.ConvertToKCRole(role))
	}

	err := c.keycloakClient.AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, rolesRep)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
	}

	return err
}

func (c *component) DeleteClientRolesFromUser(ctx context.Context, realmName, userID, clientID string, roleID string, roleName string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	role := kc.RoleRepresentation{
		ID:   &roleID,
		Name: &roleName,
	}

	err := c.keycloakClient.DeleteClientRolesFromUserRoleMapping(accessToken, realmName, userID, clientID, []kc.RoleRepresentation{role})

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
	}

	return err
}

func (c *component) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var pwd string
	var err error
	var credKc kc.CredentialRepresentation
	var passwordType = "password"
	credKc.Type = &passwordType

	if password.Value == nil {
		// the commented code respects the following scenario: if the realm has a pwd policy, the generated pwd respects this policy
		/*
			// no password value was provided; a new password, that respects the password policy of the realm, will be generated
			var minLength int = 8

			//obtain password policy
			realmKc, err := c.keycloakClient.GetRealm(accessToken, realmName)
			if err == nil {
				// generate password according to the policy of the realm
				pwd, err = internal.GeneratePassword(realmKc.PasswordPolicy, minLength, userID)
				if err != nil {
					return pwd, err
				}
				credKc.Value = &pwd
			} else {
				return "", err
			}
		*/
		// generate a password of the format UpperCase + 6 digits + LowerCase
		var nbUpperCase = 1
		var nbDigits = 6
		var nbLowerCase = 1
		pwd = keycloakb.GenerateInitialCode(nbUpperCase, nbDigits, nbLowerCase)
		credKc.Value = &pwd
	} else {
		credKc.Value = password.Value
	}

	err = c.keycloakClient.ResetPassword(accessToken, realmName, userID, credKc)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return pwd, err
	}

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "INIT_PASSWORD", realmName, userID, events.CtEventUnknownUsername, nil))

	return pwd, nil
}

func (c *component) ExecuteActionsEmail(ctx context.Context, realmName string, userID string, requiredActions []api.RequiredAction, paramKV ...string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var actions = []string{}
	for _, requiredAction := range requiredActions {
		actions = append(actions, string(requiredAction))
		if string(requiredAction) == initPasswordAction {
			//store the API call into the DB
			c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "INIT_PASSWORD", realmName, userID, events.CtEventUnknownUsername, nil))
		}
	}

	//store the API call into the DB with the parameters and the required actions
	listActions := strings.Join(actions, ",")
	values := append(paramKV, "required_actions", listActions)

	details := map[string]string{}
	for i := 0; i+1 < len(values); i += 2 {
		details[values[i]] = values[i+1]
	}

	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "ACTION_EMAIL", realmName, userID, events.CtEventUnknownUsername, details))

	err := c.keycloakClient.ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions, paramKV...)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
	}

	return err
}

func (c *component) RevokeAccreditations(ctx context.Context, realmName string, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var kcUser, err = c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user from keycloak", "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)
	var revokedAccreditations []keycloakb.AccreditationRepresentation
	var eventReporter = func(accred keycloakb.AccreditationRepresentation) {
		revokedAccreditations = append(revokedAccreditations, accred)
	}
	if !keycloakb.RevokeAccreditations(&kcUser, eventReporter) {
		return errorhandler.CreateNotFoundError("accreditations")
	}

	err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to updated keycloak user", "err", err.Error())
		return err
	}

	for _, accred := range revokedAccreditations {
		c.reportAccreditationRevokedEvent(ctx, realmName, userID, *kcUser.Username, accred)
	}

	return nil
}

func (c *component) SendSmsCode(ctx context.Context, realmName string, userID string) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	smsCodeKc, err := c.keycloakClient.SendSmsCode(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "SMS_CHALLENGE", realmName, userID, events.CtEventUnknownUsername, nil))

	return *smsCodeKc.Code, err
}

func (c *component) SendOnboardingEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, paramKV ...string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	return c.genericSendOnboardingEmail(ctx, accessToken, realmName, userID, customerRealm, reminder, paramKV...)
}

func (c *component) SendOnboardingEmailInSocialRealm(ctx context.Context, userID string, customerRealm string, reminder bool, paramKV ...string) error {
	var accessToken, err = c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Info(ctx, "msg", "Fails to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	return c.genericSendOnboardingEmail(ctx, accessToken, c.socialRealmName, userID, customerRealm, reminder, paramKV...)
}

func (c *component) genericSendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, customerRealm string, reminder bool, paramKV ...string) error {
	// Get Realm configuration from database
	realmConf, err := c.configDBModule.GetConfiguration(ctx, customerRealm)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get realm configuration from database", "err", err.Error())
		return err
	}

	if (realmConf.OnboardingRedirectURI == nil || *realmConf.OnboardingRedirectURI == "") ||
		(realmConf.OnboardingClientID == nil || *realmConf.OnboardingClientID == "") {
		return errorhandler.CreateEndpointNotEnabled(constants.MsgErrNotConfigured)
	}

	// Retrieve user
	kcUser, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't retrieve user", "userID", userID, "err", err.Error())
		return err
	}

	// Ensure user is not already onboarded
	alreadyOnboarded, err := c.onboardingModule.OnboardingAlreadyCompleted(kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Invalid OnboardingCompleted attribute for user", "userID", kcUser.ID, "err", err.Error())
		return err
	}

	if alreadyOnboarded {
		return errorhandler.CreateBadRequestError(constants.MsgErrAlreadyOnboardedUser)
	}

	onboardingRedirectURI, err := c.onboardingModule.ComputeOnboardingRedirectURI(ctx, realmName, customerRealm, realmConf)
	if err != nil {
		return err
	}

	// Send email
	err = c.onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID,
		*kcUser.Username, *realmConf.OnboardingClientID, onboardingRedirectURI, customerRealm, reminder, paramKV...)
	if err != nil {
		return err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "EMAIL_ONBOARDING_SENT", realmName, userID, *kcUser.Username, nil))

	return nil
}

/* REMOVE_THIS_3901 : start */

// KeycloakURIProvider interface
type KeycloakURIProvider interface {
	GetBaseURI(realm string) string
}

// SendMigrationEmail sends a migration email
func (c *component) SendMigrationEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, lifespan *int) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// Retieve user
	kcUser, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't retrieve user", "userID", userID, "err", err.Error())
		return err
	}

	// Ensure user is not already onboarded
	alreadyOnboarded, err := c.onboardingModule.OnboardingAlreadyCompleted(kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Invalid OnboardingCompleted attribute for user", "userID", kcUser.ID, "err", err.Error())
		return err
	}

	if alreadyOnboarded {
		return errorhandler.CreateBadRequestError(constants.MsgErrAlreadyOnboardedUser)
	}

	// Send email
	var migrationOnboardingClientID = "migration-abilis"
	err = c.sendMigrationEmail(ctx, accessToken, realmName, userID,
		*kcUser.Username, migrationOnboardingClientID, customerRealm, reminder, lifespan)
	if err != nil {
		return err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "EMAIL_MIGRATION_SENT", realmName, userID, *kcUser.Username, nil))

	return nil
}

func (c *component) sendMigrationEmail(ctx context.Context, accessToken string, realmName string, userID string, username string,
	onboardingClientID string, themeRealmName string, reminder bool, lifespan *int) error {
	var kcURL = fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/auth", c.kcURIProvider.GetBaseURI(realmName), realmName)
	redirectURL, err := url.Parse(kcURL)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't parse keycloak URL", "err", err.Error())
		return err
	}

	var parameters = url.Values{}
	parameters.Add("client_id", onboardingClientID)
	parameters.Add("scope", "openid")
	parameters.Add("response_type", "code")
	parameters.Add("redirect_uri", "https://my.trustid.ch/")
	parameters.Add("login_hint", username)

	redirectURL.RawQuery = parameters.Encode()

	var actions = []string{"ct-verify-email", "set-onboarding-token", "migration-action"}
	if reminder {
		actions = append(actions, "reminder-action")
	}
	var additionalParams = []string{"client_id", onboardingClientID, "redirect_uri", redirectURL.String(), "themeRealm", themeRealmName}
	if lifespan != nil {
		additionalParams = append(additionalParams, "lifespan", strconv.Itoa(*lifespan))
	}
	err = c.keycloakClient.ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions, additionalParams...)
	if err != nil {
		c.logger.Warn(ctx, "msg", "ExecuteActionsEmail failed", "err", err.Error())
		return err
	}

	return nil
}

/* REMOVE_THIS_3901 : end */

func (c *component) SendReminderEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	err := c.keycloakClient.SendReminderEmail(accessToken, realmName, userID, paramKV...)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
	}

	return err
}

func (c *component) ResetSmsCounter(ctx context.Context, realmName, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the user representation
	userKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//reset the counters, if the smsSent or smsAttempts attributes exist
	if userKc.Attributes != nil {
		var m = *userKc.Attributes
		if m["smsSent"] != nil || m["smsAttempts"] != nil {
			// ensure there is no unencrypted PII
			keycloakb.ConvertLegacyAttribute(&userKc)
			userKc.SetAttributeInt(constants.AttrbSmsSent, 0)
			userKc.SetAttributeInt(constants.AttrbSmsAttempts, 0)
			err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, userKc)
			if err != nil {
				c.logger.Warn(ctx, "err", err.Error())
				return err
			}
		}
	}
	return nil
}

func (c *component) CreateRecoveryCode(ctx context.Context, realmName, userID string) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	recoveryCodeKc, err := c.keycloakClient.CreateRecoveryCode(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "CREATE_RECOVERY_CODE", realmName, userID, events.CtEventUnknownUsername, nil))

	return *recoveryCodeKc.Code, err
}

func (c *component) CreateActivationCode(ctx context.Context, realmName, userID string) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	activationCodeKc, err := c.keycloakClient.CreateActivationCode(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "CREATE_ACTIVATION_CODE", realmName, userID, events.CtEventUnknownUsername, nil))

	return *activationCodeKc.Code, err
}

func (c *component) GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	credsKc, err := c.keycloakClient.GetCredentials(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var credsRep = []api.CredentialRepresentation{}
	for _, credKc := range credsKc {
		credsRep = append(credsRep, api.ConvertCredential(&credKc))
	}

	return credsRep, err
}

func (c *component) DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// Check that credential is removable
	var err = keycloakb.CheckRemovableMFA(ctx, credentialID, true, func() ([]kc.CredentialRepresentation, error) {
		return c.keycloakClient.GetCredentials(accessToken, realmName, userID)
	}, c.logger)
	if err != nil {
		return err
	}

	err = c.keycloakClient.DeleteCredential(accessToken, realmName, userID, credentialID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	details := map[string]string{}
	details[eventCredentialID] = credentialID

	// Call to CheckRemovableMFA ensures credential is a MFA: record the event 2ND_FACTOR_REMOVED in the audit DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "2ND_FACTOR_REMOVED", realmName, userID, events.CtEventUnknownUsername, details))

	return err
}

func (c *component) ResetCredentialFailuresForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var credType, err = c.getCredentialType(ctx, realmName, userID, credentialID)
	if err != nil {
		c.logger.Info(ctx, "msg", "Can't get credential type", "err", err.Error(), "id", credentialID)
		return err
	}

	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	if credType == "ctpapercard" {
		err = c.keycloakClient.ResetPapercardFailures(accessToken, realmName, userID, credentialID)
		if err != nil {
			c.logger.Info(ctx, "msg", "Can't unlock papercard credential", "err", err.Error(), "id", credentialID)
			return err
		}
	} else {
		// Will not execute this as endpoint should check the credType
		c.logger.Info(ctx, "msg", "Unsupported credential type", "type", credType)
		return errorhandler.CreateNotFoundError("credential")
	}

	return nil
}

func (c *component) getCredentialType(ctx context.Context, realmName, userID, credentialID string) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var creds, err = c.keycloakClient.GetCredentials(accessToken, realmName, userID)

	if err != nil {
		return "", err
	}

	for _, cred := range creds {
		if *cred.ID == credentialID {
			return *cred.Type, nil
		}
	}

	return "", errorhandler.CreateNotFoundError("credential")
}

func (c *component) ClearUserLoginFailures(ctx context.Context, realmName, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var err = c.keycloakClient.ClearUserLoginFailures(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "LOGIN_FAILURE_CLEARED", realmName, userID, events.CtEventUnknownUsername, nil))

	return nil
}

func (c *component) GetAttackDetectionStatus(ctx context.Context, realmName, userID string) (api.AttackDetectionStatusRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var mapValues, err = c.keycloakClient.GetAttackDetectionStatus(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AttackDetectionStatusRepresentation{}, err
	}

	return api.ConvertAttackDetectionStatus(mapValues), nil
}

func (c *component) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetRolesWithAttributes(accessToken, realmName)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range rolesKc {
		if c.isBusinessRole(roleKc) {
			rolesRep = append(rolesRep, api.ConvertToAPIRole(roleKc))
		}
	}

	return rolesRep, nil
}

func (c *component) isBusinessRole(role kc.RoleRepresentation) bool {
	if role.Attributes != nil {
		flag, ok := (*role.Attributes)[businessRoleFlag]
		return ok && len(flag) == 1 && flag[0] == "true"
	}
	return false
}

func (c *component) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var roleRep api.RoleRepresentation
	roleKc, err := c.getBusinessRole(ctx, accessToken, realmName, roleID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.RoleRepresentation{}, err
	}

	roleRep.ID = roleKc.ID
	roleRep.Name = roleKc.Name
	roleRep.Composite = roleKc.Composite
	roleRep.ClientRole = roleKc.ClientRole
	roleRep.ContainerID = roleKc.ContainerID
	roleRep.Description = roleKc.Description

	// Filter out the business role flag
	if roleKc.Attributes != nil {
		roleRep.Attributes = roleKc.Attributes
		delete(*roleRep.Attributes, businessRoleFlag)
	}

	return roleRep, nil
}

func (c *component) CreateRole(ctx context.Context, realmName string, role api.RoleRepresentation) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var roleRep = api.ConvertToKCRole(role)

	attributes := map[string][]string{
		businessRoleFlag: {"true"},
	}
	roleRep.Attributes = &attributes

	locationURL, err := c.keycloakClient.CreateRole(accessToken, realmName, roleRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	//retrieve the role ID
	reg := regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)
	roleID := string(reg.Find([]byte(locationURL)))

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_ROLE_CREATION", realmName, map[string]string{events.CtEventRoleID: roleID, events.CtEventRoleName: *role.Name}))

	return locationURL, nil
}

func (c *component) getBusinessRole(ctx context.Context, accessToken string, realmName string, roleID string) (kc.RoleRepresentation, error) {
	role, err := c.keycloakClient.GetRole(accessToken, realmName, roleID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return kc.RoleRepresentation{}, err
	}

	if !c.isBusinessRole(role) {
		return kc.RoleRepresentation{}, errorhandler.CreateNotFoundError(prmRoleID)
	}

	return role, nil
}

func (c *component) UpdateRole(ctx context.Context, realmName string, roleID string, role api.RoleRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	kcRole, err := c.getBusinessRole(ctx, accessToken, realmName, roleID)
	if err != nil {
		return err
	}

	kcRole.ClientRole = role.ClientRole
	kcRole.Composite = role.Composite
	kcRole.ContainerID = role.ContainerID
	kcRole.Description = role.Description

	// We update the attributes but keep the business role flag
	businessRoleFlagValue := (*kcRole.Attributes)[businessRoleFlag]
	if role.Attributes != nil {
		kcRole.Attributes = role.Attributes
	} else {
		kcRole.Attributes = &map[string][]string{}
	}
	(*kcRole.Attributes)[businessRoleFlag] = businessRoleFlagValue

	if err = c.keycloakClient.UpdateRole(accessToken, realmName, roleID, kcRole); err != nil {
		c.logger.Warn(ctx, "msg", "Could not update role", "realm", realmName, "role", roleID, "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_ROLE_UPDATE", realmName, map[string]string{events.CtEventRoleID: roleID, events.CtEventRoleName: *role.Name}))

	return nil
}

func (c *component) DeleteRole(ctx context.Context, realmName string, roleID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	role, err := c.getBusinessRole(ctx, accessToken, realmName, roleID)
	if err != nil {
		return err
	}

	err = c.keycloakClient.DeleteRole(accessToken, realmName, roleID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_ROLE_DELETION", realmName, map[string]string{events.CtEventRoleID: roleID, events.CtEventRoleName: *role.Name}))

	return nil
}

func (c *component) GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	groupsKc, err := c.keycloakClient.GetGroups(accessToken, realmName)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var groupsRep = []api.GroupRepresentation{}
	for _, groupKc := range groupsKc {
		var groupRep api.GroupRepresentation
		groupRep.ID = groupKc.ID
		groupRep.Name = groupKc.Name

		groupsRep = append(groupsRep, groupRep)
	}

	return groupsRep, nil
}

func (c *component) CreateGroup(ctx context.Context, realmName string, group api.GroupRepresentation) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var groupRep = api.ConvertToKCGroup(group)

	locationURL, err := c.keycloakClient.CreateGroup(accessToken, realmName, groupRep)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	//retrieve the group ID
	reg := regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)
	groupID := string(reg.Find([]byte(locationURL)))

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_GROUP_CREATION", realmName, map[string]string{events.CtEventGroupID: groupID, events.CtEventGroupName: *group.Name}))

	return locationURL, nil
}

func (c *component) DeleteGroup(ctx context.Context, realmName, groupID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	group, err := c.keycloakClient.GetGroup(accessToken, realmName, groupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	var groupName = *group.Name

	err = c.keycloakClient.DeleteGroup(accessToken, realmName, groupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	err = c.configDBModule.DeleteAllAuthorizationsWithGroup(ctx, realmName, groupName)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_GROUP_DELETION", realmName, map[string]string{events.CtEventGroupID: groupID, events.CtEventGroupName: *group.Name}))

	return nil
}

func (c *component) GetAuthorizations(ctx context.Context, realmName string, groupID string) (api.AuthorizationsRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	group, err := c.keycloakClient.GetGroup(accessToken, realmName, groupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AuthorizationsRepresentation{}, err
	}

	authorizations, err := c.configDBModule.GetAuthorizations(ctx, realmName, *group.Name)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AuthorizationsRepresentation{}, err
	}

	return api.ConvertToAPIAuthorizations(authorizations), nil
}

func (c *component) UpdateAuthorizations(ctx context.Context, realmName string, groupID string, auth api.AuthorizationsRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	group, err := c.keycloakClient.GetGroup(accessToken, realmName, groupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error(), "realm", realmName, "group", groupID)
		return err
	}

	var groupName = *group.Name

	authorizations := api.ConvertToDBAuthorizations(realmName, groupName, auth)

	if err = c.checkAllowedTargetRealmsAndGroupNames(ctx, realmName, authorizations); err != nil {
		return err
	}

	var dbAuthz []configuration.Authorization
	dbAuthz, err = c.configDBModule.GetAuthorizations(ctx, realmName, groupName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get authorizations from database", "err", err.Error(), "realm", realmName, "group", groupName)
		return err
	}
	var diff = Diff(dbAuthz, authorizations)

	// Persists the new authorizations in DB
	var addAuthz = diff[Added]
	var delAuthz = diff[Removed]
	if len(addAuthz)+len(delAuthz) > 0 {
		rawTx, err := c.configDBModule.NewTransaction(ctx)
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}
		tx := keycloakb.NewAuthorizationTransaction(rawTx)
		defer tx.Close()

		if err := tx.CreateAuthorizations(ctx, addAuthz); err != nil {
			c.logger.Warn(ctx, "mgs", "Failed creating authorizations", "err", err.Error())
			return err
		}
		if err := tx.RemoveAuthorizations(ctx, delAuthz); err != nil {
			c.logger.Warn(ctx, "mgs", "Failed deleting authorizations", "err", err.Error())
			return err
		}

		if err = tx.Commit(); err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}
		c.logger.Info(ctx, "msg", "Updated authorizations", "add_count", len(addAuthz), "del_count", len(delAuthz))

		err = c.kafkaAuthReloadProducer.SendMessageBytes([]byte{})
		if err != nil {
			c.logger.Warn(ctx, "kafka", "Failed to send message", "err", err.Error())
		}

		c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_AUTHORIZATIONS_UPDATE", realmName, map[string]string{events.CtEventGroupName: groupName}))
	}

	return nil
}

func (c *component) AddAuthorization(ctx context.Context, realmName string, groupID string, authz api.AuthorizationsRepresentation) error {
	// This method needs to reload the authorizations matrix to synch the matrix cache with the DB
	// If not, it will not be compatible with potential previous call to AddAuthorization or DeleteAuthorization.
	err := c.authChecker.ReloadAuthorizations(ctx)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	group, err := c.keycloakClient.GetGroup(accessToken, realmName, groupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	var groupName = *group.Name

	authorizations := api.ConvertToDBAuthorizations(realmName, groupName, authz)

	if err = c.checkAllowedTargetRealmsAndGroupNames(ctx, realmName, authorizations); err != nil {
		return err
	}

	if err = validateScopes(authorizations); err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	// Persists the new authorizations in DB
	{
		tx, err := c.configDBModule.NewTransaction(ctx)
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}
		defer tx.Close()

		for _, authz := range authorizations {
			scope, err := getScope(authz)
			if err != nil {
				c.logger.Warn(ctx, "err", err.Error())
				return err
			}

			var exists error
			if scope == security.ScopeGroup {
				exists = c.authChecker.CheckAuthorizationForGroupsOnTargetGroup(*authz.RealmID, []string{*authz.GroupName}, *authz.Action, *authz.TargetRealmID, *authz.TargetGroupName)
			} else {
				exists = c.authChecker.CheckAuthorizationForGroupsOnTargetRealm(*authz.RealmID, []string{*authz.GroupName}, *authz.Action, *authz.TargetRealmID)
			}

			// If the authorization does not exist yet
			if exists != nil {
				// Cleaning. Remove the authorizations that are included in the new one.
				if *authz.TargetRealmID == "*" {
					err = c.configDBModule.CleanAuthorizationsActionForEveryRealms(ctx, *authz.RealmID, *authz.GroupName, *authz.Action)
				} else if authz.TargetGroupName != nil && *authz.TargetGroupName == "*" {
					err = c.configDBModule.CleanAuthorizationsActionForRealm(ctx, *authz.RealmID, *authz.GroupName, *authz.TargetRealmID, *authz.Action)
				}
				if err != nil {
					c.logger.Warn(ctx, "err", err.Error())
					return err
				}

				//Creation of the authorization
				err = c.configDBModule.CreateAuthorization(ctx, authz)
				if err != nil {
					c.logger.Warn(ctx, "err", err.Error())
					return err
				}
			}
		}

		err = tx.Commit()
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}
	}
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_AUTHORIZATIONS_PUT", realmName, map[string]string{events.CtEventGroupName: groupName}))

	return nil
}

func (c *component) parseTargetGroupName(accessToken string, targetRealm string, targetGroupID string) (*string, error) {
	var targetGroupName *string
	if targetGroupID == "*" {
		targetGroupName = &targetGroupID
	} else if targetGroupID != "" {
		targetGroup, err := c.keycloakClient.GetGroup(accessToken, targetRealm, targetGroupID)
		if err != nil {
			return nil, err
		}
		targetGroupName = targetGroup.Name
	}
	return targetGroupName, nil
}

func (c *component) GetAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) (api.AuthorizationMessage, error) {
	// This method needs to reload the authorizations matrix to synch the matrix cache with the DB
	// If not, it will not be compatible with potential previous call to AddAuthorization or DeleteAuthorization.
	err := c.authChecker.ReloadAuthorizations(ctx)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AuthorizationMessage{}, err
	}

	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	group, err := c.keycloakClient.GetGroup(accessToken, realmName, groupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AuthorizationMessage{}, err
	}

	targetGroupName, err := c.parseTargetGroupName(accessToken, targetRealm, targetGroupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AuthorizationMessage{}, err
	}

	authz := configuration.Authorization{
		RealmID:         &realmName,
		GroupName:       group.Name,
		Action:          &actionReq,
		TargetRealmID:   &targetRealm,
		TargetGroupName: targetGroupName,
	}

	err = validateScope(authz)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AuthorizationMessage{}, err
	}

	scope, err := getScope(authz)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.AuthorizationMessage{}, err
	}

	if scope == security.ScopeGroup {
		err = c.authChecker.CheckAuthorizationForGroupsOnTargetGroup(*authz.RealmID, []string{*authz.GroupName}, *authz.Action, *authz.TargetRealmID, *authz.TargetGroupName)
	} else {
		err = c.authChecker.CheckAuthorizationForGroupsOnTargetRealm(*authz.RealmID, []string{*authz.GroupName}, *authz.Action, *authz.TargetRealmID)
	}

	if err != nil {
		return api.AuthorizationMessage{Authorized: false}, nil
	}
	return api.AuthorizationMessage{Authorized: true}, nil
}

func (c *component) DeleteAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	group, err := c.keycloakClient.GetGroup(accessToken, realmName, groupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	targetGroupName, err := c.parseTargetGroupName(accessToken, targetRealm, targetGroupID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	authz := configuration.Authorization{
		RealmID:         &realmName,
		GroupName:       group.Name,
		Action:          &actionReq,
		TargetRealmID:   &targetRealm,
		TargetGroupName: targetGroupName,
	}

	err = validateScope(authz)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	exists, err := c.configDBModule.AuthorizationExists(ctx, *authz.RealmID, *authz.GroupName, *authz.TargetRealmID, authz.TargetGroupName, *authz.Action)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	if exists {
		err = c.configDBModule.DeleteAuthorization(ctx, *authz.RealmID, *authz.GroupName, *authz.TargetRealmID, authz.TargetGroupName, *authz.Action)
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}
		c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventFromContext(ctx, c.logger, c.originEvent, "API_AUTHORIZATION_DELETE", realmName, map[string]string{"action": *authz.Action}))
	}

	return nil
}

func (c *component) checkAllowedTargetRealmsAndGroupNames(ctx context.Context, realmName string, authorizations []configuration.Authorization) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var allowedTargetRealmsAndGroupNames = make(map[string]map[string]struct{})
	// Validate the authorizations provided
	{
		// Retrieve the info needed for validation
		{
			realms, err := c.keycloakClient.GetRealms(accessToken)
			if err != nil {
				c.logger.Warn(ctx, "err", err.Error())
				return err
			}

			// * is allowed as targetRealm only for master
			if realmName == "master" {
				allowedTargetRealmsAndGroupNames["*"] = make(map[string]struct{})
				allowedTargetRealmsAndGroupNames["*"]["*"] = struct{}{}
			}

			for _, realm := range realms {
				var realmID = *realm.ID
				allowedTargetRealmsAndGroupNames[realmID] = make(map[string]struct{})

				groups, err := c.keycloakClient.GetGroups(accessToken, realmID)
				if err != nil {
					c.logger.Warn(ctx, "err", err.Error())
					return err
				}

				for _, group := range groups {
					allowedTargetRealmsAndGroupNames[realmID][*group.Name] = struct{}{}
				}

				allowedTargetRealmsAndGroupNames[realmID]["*"] = struct{}{}
			}
		}

		// Perform validation
		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return errorhandler.CreateBadRequestError(constants.MsgErrInvalidParam + "." + constants.Authorization)
		}
	}
	return nil
}

func (c *component) GetActions(ctx context.Context) ([]api.ActionRepresentation, error) {
	var apiActions = []api.ActionRepresentation{}

	// The communications API and some tasks are published internally only.
	// To be able to configure the rights from the BO we add them here.
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.ManagementAPI, security.CommunicationAPI, security.TaskAPI) {
		var name = action.Name
		var scope = string(action.Scope)

		apiActions = append(apiActions, api.ActionRepresentation{
			Name:  &name,
			Scope: &scope,
		})
	}

	return apiActions, nil
}

func (c *component) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetClientRoles(accessToken, realmName, idClient)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.ID = roleKc.ID
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerID = roleKc.ContainerID
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var roleRep kc.RoleRepresentation
	roleRep.ID = role.ID
	roleRep.Name = role.Name
	roleRep.Composite = role.Composite
	roleRep.ClientRole = role.ClientRole
	roleRep.ContainerID = role.ContainerID
	roleRep.Description = role.Description

	locationURL, err := c.keycloakClient.CreateClientRole(accessToken, realmName, clientID, roleRep)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	return locationURL, nil
}

func (c *component) DeleteClientRole(ctx context.Context, realmName, clientID string, roleID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	role, err := c.keycloakClient.GetRole(accessToken, realmName, roleID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return errorhandler.CreateNotFoundError("role")
	}

	if role.ClientRole == nil || role.ContainerID == nil || !*role.ClientRole || *role.ContainerID != clientID {
		err := errorhandler.CreateNotFoundError("role")
		c.logger.Warn(ctx, err, err.Error())
		return err
	}

	return c.keycloakClient.DeleteRole(accessToken, realmName, roleID)
}

// Retrieve the configuration from the database
func (c *component) GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the realm config from Keycloak
	realmConfig, err := c.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.RealmCustomConfiguration{}, err
	}
	// from the realm ID, fetch the custom configuration
	realmID := realmConfig.ID
	config, err := c.configDBModule.GetConfiguration(ctx, *realmID)
	// DB error
	if err != nil {
		switch e := errors.Cause(err).(type) {
		case errorhandler.Error:
			c.logger.Warn(ctx, "msg", e.Error())
			return api.CreateDefaultRealmCustomConfiguration(), nil
		default:
			c.logger.Error(ctx, "err", e.Error())
			return api.RealmCustomConfiguration{}, err
		}
	}

	return api.ConvertRealmCustomConfigurationFromDBStruct(config), nil
}

// Update the configuration in the database; verify that the content of the configuration is coherent with Keycloak configuration
func (c *component) UpdateRealmCustomConfiguration(ctx context.Context, realmName string, customConfig api.RealmCustomConfiguration) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the realm config from Keycloak
	realmConfig, err := c.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		c.logger.Error(ctx, "err", err.Error())
		return err
	}
	// get the desired client (from its ID)
	clients, err := c.keycloakClient.GetClients(accessToken, realmName)
	if err != nil {
		c.logger.Error(ctx, "err", err.Error())
		return err
	}

	// Both DefaultClientID and DefaultRedirectURI must be specified together or not at all
	if (customConfig.DefaultClientID == nil && customConfig.DefaultRedirectURI != nil) ||
		(customConfig.DefaultClientID != nil && customConfig.DefaultRedirectURI == nil) {
		return errorhandler.CreateBadRequestError(constants.MsgErrInvalidParam + "." + constants.ClientID + "AND" + constants.RedirectURI)
	}

	if !c.matchClients(customConfig, clients) {
		return errorhandler.Error{
			Status:  400,
			Message: keycloakb.ComponentName + "." + constants.MsgErrInvalidParam + "." + constants.ClientID + "OR" + constants.RedirectURI,
		}
	}

	// transform customConfig object into DTO
	var config = configuration.RealmConfiguration{
		DefaultClientID:                     customConfig.DefaultClientID,
		DefaultRedirectURI:                  customConfig.DefaultRedirectURI,
		APISelfAuthenticatorDeletionEnabled: customConfig.APISelfAuthenticatorDeletionEnabled,
		APISelfPasswordChangeEnabled:        customConfig.APISelfPasswordChangeEnabled,
		APISelfAccountEditingEnabled:        customConfig.APISelfAccountEditingEnabled,
		APISelfAccountDeletionEnabled:       customConfig.APISelfAccountDeletionEnabled,
		ShowAuthenticatorsTab:               customConfig.ShowAuthenticatorsTab,
		ShowPasswordTab:                     customConfig.ShowPasswordTab,
		ShowProfileTab:                      customConfig.ShowProfileTab,
		ShowAccountDeletionButton:           customConfig.ShowAccountDeletionButton,
		SelfServiceDefaultTab:               customConfig.SelfServiceDefaultTab,
		RedirectCancelledRegistrationURL:    customConfig.RedirectCancelledRegistrationURL,
		RedirectSuccessfulRegistrationURL:   customConfig.RedirectSuccessfulRegistrationURL,
		OnboardingRedirectURI:               customConfig.OnboardingRedirectURI,
		OnboardingClientID:                  customConfig.OnboardingClientID,
		SelfRegisterGroupNames:              customConfig.SelfRegisterGroupNames,
		BarcodeType:                         customConfig.BarcodeType,
		AllowedBackURLs:                     customConfig.AllowedBackURLs,
	}

	// from the realm ID, update the custom configuration in the DB
	realmID := realmConfig.ID
	return c.configDBModule.StoreOrUpdateConfiguration(ctx, *realmID, config)
}

func (c *component) matchClients(customConfig api.RealmCustomConfiguration, clients []kc.ClientRepresentation) bool {
	if customConfig.DefaultClientID == nil || customConfig.DefaultRedirectURI == nil {
		return true
	}

	for _, client := range clients {
		if *client.ClientID != *customConfig.DefaultClientID {
			continue
		}
		for _, redirectURI := range *client.RedirectUris {
			// escape the regex-specific characters (dots for intance)...
			matcher := regexp.QuoteMeta(redirectURI)
			// ... but keep the stars
			matcher = strings.Replace(matcher, "\\*", "*", -1)
			if match, _ := regexp.MatchString(matcher, *customConfig.DefaultRedirectURI); match {
				return true
			}
		}
	}

	return false
}

func (c *component) GetUserRealmBackOfficeConfiguration(ctx context.Context, realmName string) (api.BackOfficeConfiguration, error) {
	var groups = ctx.Value(cs.CtContextGroups).([]string)
	var dbResult, err = c.configDBModule.GetBackOfficeConfiguration(ctx, realmName, groups)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	return api.BackOfficeConfiguration(dbResult), nil
}

// Retrieve the admin configuration from the database
func (c *component) GetRealmAdminConfiguration(ctx context.Context, realmName string) (api.RealmAdminConfiguration, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the realm config from Keycloak
	realmConfig, err := c.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.RealmAdminConfiguration{}, err
	}

	var config configuration.RealmAdminConfiguration
	config, err = c.configDBModule.GetAdminConfiguration(ctx, *realmConfig.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return api.CreateDefaultRealmAdminConfiguration(), nil
		}
		c.logger.Warn(ctx, "err", err.Error())
		return api.RealmAdminConfiguration{}, err
	}

	return api.ConvertRealmAdminConfigurationFromDBStruct(config), nil
}

// Update the configuration in the database
func (c *component) UpdateRealmAdminConfiguration(ctx context.Context, realmName string, adminConfig api.RealmAdminConfiguration) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the realm config from Keycloak
	realmRepr, err := c.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	err = c.configDBModule.StoreOrUpdateAdminConfiguration(ctx, *realmRepr.ID, adminConfig.ConvertToDBStruct())
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	return nil
}

func (c *component) GetRealmUserProfile(ctx context.Context, realmName string) (apicommon.ProfileRepresentation, error) {
	var profile, err = c.profileCache.GetRealmUserProfile(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get users profile", "err", err.Error())
		return apicommon.ProfileRepresentation{}, err
	}

	return apicommon.ProfileToAPI(profile, apiName), nil
}

func (c *component) GetRealmBackOfficeConfiguration(ctx context.Context, realmName string, groupName string) (api.BackOfficeConfiguration, error) {
	var dbResult, err = c.configDBModule.GetBackOfficeConfiguration(ctx, realmName, []string{groupName})
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	return api.BackOfficeConfiguration(dbResult), nil
}

func (c *component) UpdateRealmBackOfficeConfiguration(ctx context.Context, realmID string, groupName string, configuration api.BackOfficeConfiguration) error {
	var dbResult, err = c.configDBModule.GetBackOfficeConfiguration(ctx, realmID, []string{groupName})
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	err = c.removeObsoleteItemsFromBackOfficeConfiguration(ctx, realmID, groupName, dbResult, configuration)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	err = c.addBackOfficeConfigurationNewItems(ctx, realmID, groupName, dbResult, configuration)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
	}

	return err
}

func (c *component) removeObsoleteItemsFromBackOfficeConfiguration(ctx context.Context, realmID string, groupName string, oldConf dto.BackOfficeConfiguration, newConf api.BackOfficeConfiguration) error {
	var err error

	// Remove elements which were present in the old configuration and are not present in the new one
	for existingRealm, existingRealmConf := range oldConf {
		if newRealmConf, ok := newConf[existingRealm]; !ok {
			err = c.configDBModule.DeleteBackOfficeConfiguration(ctx, realmID, groupName, existingRealm, nil, nil)
			if err != nil {
				return err
			}
		} else {
			for existingType, existingTypeConf := range existingRealmConf {
				if newTypeConf, ok := newRealmConf[existingType]; !ok {
					err = c.configDBModule.DeleteBackOfficeConfiguration(ctx, realmID, groupName, existingRealm, &existingType, nil)
					if err != nil {
						return err
					}
				} else {
					for _, existingGroupName := range existingTypeConf {
						if !c.findString(newTypeConf, existingGroupName) {
							err = c.configDBModule.DeleteBackOfficeConfiguration(ctx, realmID, groupName, existingRealm, &existingType, &existingGroupName)
							if err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func (c *component) addBackOfficeConfigurationNewItems(ctx context.Context, realmID string, groupName string, oldConf dto.BackOfficeConfiguration, newConf api.BackOfficeConfiguration) error {
	var err error

	// Add elements which are in the new configuration and are not present in the old one
	for newRealmID, newRealmConf := range newConf {
		if oldRealmConf, ok := oldConf[newRealmID]; !ok {
			for boType, boGroups := range newRealmConf {
				err = c.configDBModule.InsertBackOfficeConfiguration(ctx, realmID, groupName, newRealmID, boType, boGroups)
				if err != nil {
					return err
				}
			}
		} else {
			for newTypeConf, newGroups := range newRealmConf {
				if oldGroups, ok := oldRealmConf[newTypeConf]; !ok {
					err = c.configDBModule.InsertBackOfficeConfiguration(ctx, realmID, groupName, newRealmID, newTypeConf, newGroups)
					if err != nil {
						return err
					}
				} else {
					for _, newGroupName := range newGroups {
						if !c.findString(oldGroups, newGroupName) {
							err = c.configDBModule.InsertBackOfficeConfiguration(ctx, realmID, groupName, newRealmID, newTypeConf, []string{newGroupName})
							if err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (c *component) findString(groups []string, searchGroup string) bool {
	for _, aGroup := range groups {
		if aGroup == searchGroup {
			return true
		}
	}
	return false
}

func (c *component) GetFederatedIdentities(ctx context.Context, realmName string, userID string) ([]api.FederatedIdentityRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var kcFedIds, err = c.keycloakClient.GetFederatedIdentities(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get federated identities", "err", err.Error())
		return nil, err
	}
	if len(kcFedIds) == 0 {
		// Don't return a nil slice but a 0-size array
		return []api.FederatedIdentityRepresentation{}, nil
	}
	var res []api.FederatedIdentityRepresentation
	for _, kcFedID := range kcFedIds {
		res = append(res, api.FederatedIdentityRepresentation{
			UserID:           kcFedID.UserID,
			Username:         kcFedID.UserName,
			IdentityProvider: kcFedID.IdentityProvider,
		})
	}
	return res, nil
}

func (c *component) LinkShadowUser(ctx context.Context, realmName string, userID string, provider string, fedID api.FederatedIdentityRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var fedIDKC = api.ConvertToKCFedID(fedID)

	err := c.keycloakClient.LinkShadowUser(accessToken, realmName, userID, provider, fedIDKC)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't link shadow user", "err", err.Error())
		return err
	}
	return nil
}

func (c *component) GetIdentityProviders(ctx context.Context, realmName string) ([]api.IdentityProviderRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	idps, err := c.keycloakClient.GetIdps(accessToken, realmName)
	if err != nil {
		return []api.IdentityProviderRepresentation{}, err
	}

	var apiIdps = make([]api.IdentityProviderRepresentation, 0)
	for _, idp := range idps {
		apiIdps = append(apiIdps, api.ConvertToAPIIdentityProvider(idp))
	}

	return apiIdps, nil
}
