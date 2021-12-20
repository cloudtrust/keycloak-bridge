package management

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	initPasswordAction = "sms-password-set"
	businessRoleFlag   = "BUSINESS_ROLE_FLAG"
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
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation) (string, error)
	GetClientRoleMappings(accessToken string, realmName, userID, clientID string) ([]kc.RoleRepresentation, error)
	AddClientRolesToUserRoleMapping(accessToken string, realmName, userID, clientID string, roles []kc.RoleRepresentation) error
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
	LinkShadowUser(accessToken string, realmName string, userID string, provider string, fedID kc.FederatedIdentityRepresentation) error
	ClearUserLoginFailures(accessToken string, realmName, userID string) error
	GetAttackDetectionStatus(accessToken string, realmName, userID string) (map[string]interface{}, error)
}

// UsersDetailsDBModule is the interface from the users module
type UsersDetailsDBModule interface {
	StoreOrUpdateUserDetails(ctx context.Context, realm string, user dto.DBUser) error
	GetUserDetails(ctx context.Context, realm string, userID string) (dto.DBUser, error)
	DeleteUserDetails(ctx context.Context, realm string, userID string) error
	GetChecks(ctx context.Context, realm string, userID string) ([]dto.DBCheck, error)
}

// OnboardingModule is the interface for the onboarding process
type OnboardingModule interface {
	OnboardingAlreadyCompleted(kc.UserRepresentation) (bool, error)
	SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, username string,
		onboardingClientID string, onboardingRedirectURI string, themeRealmName string, reminder bool, lifespan *int) error
	CreateUser(ctx context.Context, accessToken, realmName, targetRealmName string, kcUser *kc.UserRepresentation) (string, error)
}

// GlnVerifier interface allows to check validity of a GLN
type GlnVerifier interface {
	ValidateGLN(firstName, lastName, gln string) error
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

	ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) (string, error)
	ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []api.RequiredAction, paramKV ...string) error
	SendSmsCode(ctx context.Context, realmName string, userID string) (string, error)
	SendOnboardingEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, lifespan *int) error
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
	DeleteRole(ctx context.Context, realmName string, roleID string) error
	GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error)
	CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error)

	GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error)
	CreateGroup(ctx context.Context, realmName string, group api.GroupRepresentation) (string, error)
	DeleteGroup(ctx context.Context, realmName string, groupID string) error
	GetAuthorizations(ctx context.Context, realmName string, groupID string) (api.AuthorizationsRepresentation, error)
	UpdateAuthorizations(ctx context.Context, realmName string, groupID string, group api.AuthorizationsRepresentation) error

	GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error)
	UpdateRealmCustomConfiguration(ctx context.Context, realmID string, customConfig api.RealmCustomConfiguration) error
	GetRealmAdminConfiguration(ctx context.Context, realmName string) (api.RealmAdminConfiguration, error)
	UpdateRealmAdminConfiguration(ctx context.Context, realmID string, adminConfig api.RealmAdminConfiguration) error
	GetRealmBackOfficeConfiguration(ctx context.Context, realmID string, groupName string) (api.BackOfficeConfiguration, error)
	UpdateRealmBackOfficeConfiguration(ctx context.Context, realmID string, groupName string, config api.BackOfficeConfiguration) error
	GetUserRealmBackOfficeConfiguration(ctx context.Context, realmID string) (api.BackOfficeConfiguration, error)

	LinkShadowUser(ctx context.Context, realmName string, userID string, provider string, fedID api.FederatedIdentityRepresentation) error
}

// Component is the management component.
type component struct {
	keycloakClient          KeycloakClient
	kcURIProvider           KeycloakURIProvider /* REMOVE_THIS_3901 */
	usersDBModule           UsersDetailsDBModule
	eventDBModule           database.EventsDBModule
	configDBModule          keycloakb.ConfigurationDBModule
	onboardingModule        OnboardingModule
	authorizedTrustIDGroups map[string]bool
	socialRealmName         string
	glnVerifier             GlnVerifier
	logger                  keycloakb.Logger
}

// NewComponent returns the management component.
func NewComponent(keycloakClient KeycloakClient, kcURIProvider kc.KeycloakURIProvider, usersDBModule UsersDetailsDBModule, eventDBModule database.EventsDBModule,
	configDBModule keycloakb.ConfigurationDBModule, onboardingModule OnboardingModule, authorizedTrustIDGroups []string, socialRealmName string,
	glnVerifier GlnVerifier, logger keycloakb.Logger) Component {
	/* REMOVE_THIS_3901 : remove second provided parameter */

	var authzedTrustIDGroups = make(map[string]bool)
	for _, grp := range authorizedTrustIDGroups {
		authzedTrustIDGroups[grp] = true
	}

	return &component{
		keycloakClient:          keycloakClient,
		kcURIProvider:           kcURIProvider, /* REMOVE_THIS_3901 */
		usersDBModule:           usersDBModule,
		eventDBModule:           eventDBModule,
		configDBModule:          configDBModule,
		onboardingModule:        onboardingModule,
		authorizedTrustIDGroups: authzedTrustIDGroups,
		socialRealmName:         socialRealmName,
		glnVerifier:             glnVerifier,
		logger:                  logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		keycloakb.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
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

	var userRep = api.ConvertToKCUser(user)
	userRep.SetAttributeString(constants.AttrbSource, "api")

	if termsOfUse {
		var reqActions []string
		if userRep.RequiredActions != nil {
			reqActions = *userRep.RequiredActions
		}
		reqActions = append(reqActions, "ct-terms-of-use")
		userRep.RequiredActions = &reqActions
	}

	if generateNameID {
		var oneUUID, errUUID = uuid.NewUUID()
		if errUUID != nil {
			c.logger.Warn(ctx, "msg", "Can't generate UUID", "err", errUUID.Error())
			return "", errUUID
		}
		var nameID = fmt.Sprintf("G-%s", oneUUID.String())
		userRep.SetAttributeString(constants.AttrbNameID, nameID)
	}

	if glnErr := c.checkGLN(ctx, realmName, true, user.BusinessID, &userRep); glnErr != nil {
		return "", glnErr
	}

	var locationURL string
	var err error
	if realmName == c.socialRealmName || generateUsername {
		// Ignore username and create a random one
		userRep.Username = nil
		locationURL, err = c.onboardingModule.CreateUser(ctx, accessToken, ctxRealm, realmName, &userRep)
	} else {
		// Store user in KC
		locationURL, err = c.keycloakClient.CreateUser(accessToken, ctxRealm, realmName, userRep)
	}
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	var username = ""
	if user.Username != nil {
		username = *user.Username
	}

	//retrieve the user ID
	reg := regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)
	userID := string(reg.Find([]byte(locationURL)))

	var userInfoToPersist = user.BirthLocation != nil
	userInfoToPersist = userInfoToPersist || user.Nationality != nil
	userInfoToPersist = userInfoToPersist || user.IDDocumentType != nil
	userInfoToPersist = userInfoToPersist || user.IDDocumentNumber != nil
	userInfoToPersist = userInfoToPersist || user.IDDocumentExpiration != nil
	userInfoToPersist = userInfoToPersist || user.IDDocumentCountry != nil

	if userInfoToPersist {
		// Store user in database
		err = c.usersDBModule.StoreOrUpdateUserDetails(ctx, realmName, dto.DBUser{
			UserID:               &userID,
			BirthLocation:        user.BirthLocation,
			Nationality:          user.Nationality,
			IDDocumentType:       user.IDDocumentType,
			IDDocumentNumber:     user.IDDocumentNumber,
			IDDocumentExpiration: user.IDDocumentExpiration,
			IDDocumentCountry:    user.IDDocumentCountry,
		})
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't store user details in database", "err", err.Error())
			return "", err
		}
	}

	//store the API call into the DB
	c.reportEvent(ctx, "API_ACCOUNT_CREATION", database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, username)

	return locationURL, nil
}

func (c *component) checkGLN(ctx context.Context, realm string, businessIDThere bool, businessID *string, kcUser *kc.UserRepresentation) error {
	if adminConfig, err := c.configDBModule.GetAdminConfiguration(ctx, realm); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get realm admin configuration", "realm", realm, "err", err.Error())
		return err
	} else if adminConfig.ShowGlnEditing == nil || !*adminConfig.ShowGlnEditing {
		// No GLN expected
		kcUser.RemoveAttribute(constants.AttrbBusinessID)
	} else if businessIDThere {
		// GLN enabled for this realm
		if businessID == nil {
			kcUser.RemoveAttribute(constants.AttrbBusinessID)
		} else {
			return c.glnVerifier.ValidateGLN(*kcUser.FirstName, *kcUser.LastName, *businessID)
		}
	}
	return nil
}

func (c *component) DeleteUser(ctx context.Context, realmName, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	err := c.keycloakClient.DeleteUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	err = c.usersDBModule.DeleteUserDetails(ctx, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.reportEvent(ctx, "API_ACCOUNT_DELETION", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

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

	// Retrieve info from DB user
	dbUser, err := c.usersDBModule.GetUserDetails(ctx, realmName, *userKc.ID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserRepresentation{}, err
	}

	userRep.BirthLocation = dbUser.BirthLocation
	userRep.Nationality = dbUser.Nationality
	userRep.IDDocumentType = dbUser.IDDocumentType
	userRep.IDDocumentNumber = dbUser.IDDocumentNumber
	userRep.IDDocumentExpiration = dbUser.IDDocumentExpiration
	userRep.IDDocumentCountry = dbUser.IDDocumentCountry

	//store the API call into the DB
	c.reportEvent(ctx, "GET_DETAILS", database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, username)

	return userRep, nil
}

func (c *component) isUpdated(newValue, oldValue *string) bool {
	if oldValue == nil {
		return newValue != nil
	}
	return newValue != nil && *oldValue != *newValue
}

func (c *component) UpdateUser(ctx context.Context, realmName, userID string, user api.UpdatableUserRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var userRep kc.UserRepresentation
	var removeAttributes []kc.AttributeKey

	// get the "old" user representation
	oldUserKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&oldUserKc)

	// get the "old" user infos from database
	oldDbUser, err := c.usersDBModule.GetUserDetails(ctx, realmName, userID)
	if err != nil {
		// Log warning already performed in GetUser
		return err
	}

	if realmName == c.socialRealmName {
		// Self register enabled: we can't update the username
		user.Username = oldUserKc.Username
	}

	// when the email changes, set the EmailVerified to false
	if user.Email.Defined && (user.Email.Value == nil || c.isUpdated(user.Email.Value, oldUserKc.Email)) {
		var verified = false
		user.EmailVerified = &verified
	}

	// when the phone number changes, set the PhoneNumberVerified to false
	if user.PhoneNumber.Defined && (user.PhoneNumber.Value == nil || c.isUpdated(user.PhoneNumber.Value, oldUserKc.GetAttributeString(constants.AttrbPhoneNumber))) {
		var verified = false
		user.PhoneNumberVerified = &verified
		if user.PhoneNumber.Value == nil {
			removeAttributes = append(removeAttributes, constants.AttrbPhoneNumber, constants.AttrbPhoneNumberVerified)
		}
	}

	// Update in DB user for extra infos
	// Store user in database
	var userInfosUpdated = keycloakb.IsUpdated(user.BirthLocation, oldDbUser.BirthLocation,
		user.Nationality, oldDbUser.Nationality,
		user.IDDocumentType, oldDbUser.IDDocumentType,
		user.IDDocumentNumber, oldDbUser.IDDocumentNumber,
		user.IDDocumentExpiration, oldDbUser.IDDocumentExpiration,
		user.IDDocumentCountry, oldDbUser.IDDocumentCountry)
	var oldGlnValue = oldUserKc.GetAttributeString(constants.AttrbBusinessID)
	// Check if GLN validity should be re-evaluated
	var glnUpdated = keycloakb.IsUpdated(user.FirstName, oldUserKc.FirstName,
		user.LastName, oldUserKc.LastName,
		user.BusinessID.Value, oldGlnValue,
	)
	if oldGlnValue != nil && user.BusinessID.Defined && user.BusinessID.Value == nil {
		glnUpdated = true
		removeAttributes = append(removeAttributes, constants.AttrbBusinessID)
	}

	var revokeAccreditations = userInfosUpdated || glnUpdated || keycloakb.IsUpdated(
		user.Gender, oldUserKc.GetAttributeString(constants.AttrbGender),
		user.BirthDate, oldUserKc.GetAttributeString(constants.AttrbBirthDate),
	)

	userRep = api.ConvertUpdatableToKCUser(user)

	// Merge the attributes coming from the old user representation and the updated user representation in order not to lose anything
	var mergedAttributes = make(kc.Attributes)
	mergedAttributes.Merge(oldUserKc.Attributes)
	mergedAttributes.Merge(userRep.Attributes)
	for _, key := range removeAttributes {
		delete(mergedAttributes, key)
	}

	userRep.Attributes = &mergedAttributes
	if revokeAccreditations {
		keycloakb.RevokeAccreditations(&userRep)
	}

	if glnUpdated {
		if glnErr := c.checkGLN(ctx, realmName, user.BusinessID.Defined, user.BusinessID.Value, &userRep); glnErr != nil {
			return glnErr
		}
	}

	// Update in KC
	if err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, userRep); err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB in case where user.Enable is present
	if user.Enabled != nil && (oldUserKc.Enabled == nil || *user.Enabled != *oldUserKc.Enabled) {
		c.reportLockEvent(ctx, realmName, userID, user.Username, *user.Enabled)
	}

	if userInfosUpdated {
		if keycloakb.IsUpdated(user.BirthLocation, oldDbUser.BirthLocation) {
			oldDbUser.BirthLocation = user.BirthLocation
		}

		if keycloakb.IsUpdated(user.Nationality, oldDbUser.Nationality) {
			oldDbUser.Nationality = user.Nationality
		}

		if keycloakb.IsUpdated(user.IDDocumentType, oldDbUser.IDDocumentType) {
			oldDbUser.IDDocumentType = user.IDDocumentType
		}

		if keycloakb.IsUpdated(user.IDDocumentNumber, oldDbUser.IDDocumentNumber) {
			oldDbUser.IDDocumentNumber = user.IDDocumentNumber
		}

		if keycloakb.IsUpdated(user.IDDocumentExpiration, oldDbUser.IDDocumentExpiration) {
			oldDbUser.IDDocumentExpiration = user.IDDocumentExpiration
		}

		if keycloakb.IsUpdated(user.IDDocumentCountry, oldDbUser.IDDocumentCountry) {
			oldDbUser.IDDocumentCountry = user.IDDocumentCountry
		}

		err = c.usersDBModule.StoreOrUpdateUserDetails(ctx, realmName, oldDbUser)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't store user details in database", "err", err.Error())
			return err
		}
	}

	return nil
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

	c.reportEvent(ctx, ctEventType, database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, *username)
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
	var checks, err = c.usersDBModule.GetChecks(ctx, realmName, userID)
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
		var roleRep kc.RoleRepresentation
		roleRep.ID = role.ID
		roleRep.Name = role.Name
		roleRep.Composite = role.Composite
		roleRep.ClientRole = role.ClientRole
		roleRep.ContainerID = role.ContainerID
		roleRep.Description = role.Description

		rolesRep = append(rolesRep, roleRep)
	}

	err := c.keycloakClient.AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, rolesRep)

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
	c.reportEvent(ctx, "INIT_PASSWORD", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

	return pwd, nil
}

func (c *component) ExecuteActionsEmail(ctx context.Context, realmName string, userID string, requiredActions []api.RequiredAction, paramKV ...string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var actions = []string{}
	for _, requiredAction := range requiredActions {
		actions = append(actions, string(requiredAction))
		if string(requiredAction) == initPasswordAction {
			//store the API call into the DB
			c.reportEvent(ctx, "INIT_PASSWORD", database.CtEventRealmName, realmName, database.CtEventUserID, userID)
		}
	}

	//store the API call into the DB with the parameters and the required actions
	listActions := strings.Join(actions, ",")
	values := append(paramKV, "required_actions", listActions)
	additionalInfo := database.CreateAdditionalInfo(values...)
	c.reportEvent(ctx, "ACTION_EMAIL", database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventAdditionalInfo, additionalInfo)

	err := c.keycloakClient.ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions, paramKV...)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
	}

	return err
}

func (c *component) SendSmsCode(ctx context.Context, realmName string, userID string) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	smsCodeKc, err := c.keycloakClient.SendSmsCode(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "SMS_CHALLENGE", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

	return *smsCodeKc.Code, err
}

func (c *component) SendOnboardingEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, lifespan *int) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

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

	var onboardingRedirectURI = *realmConf.OnboardingRedirectURI
	if realmName != customerRealm {
		onboardingRedirectURI += "?customerRealm=" + customerRealm
	}

	// Send email
	err = c.onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID,
		*kcUser.Username, *realmConf.OnboardingClientID, onboardingRedirectURI, customerRealm, reminder, lifespan)
	if err != nil {
		return err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "EMAIL_ONBOARDING_SENT", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

	return nil
}

/* REMOVE_THIS_3901 : start */
// KeycloakURIProvider interface
type KeycloakURIProvider interface {
	GetBaseURI(realm string) string
}

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
	c.reportEvent(ctx, "EMAIL_MIGRATION_SENT", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

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

	var actions = []string{"VERIFY_EMAIL", "set-onboarding-token", "migration-action"}
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
	c.reportEvent(ctx, "CREATE_RECOVERY_CODE", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

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
	c.reportEvent(ctx, "CREATE_ACTIVATION_CODE", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

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

	// Call to CheckRemovableMFA ensures credential is a MFA: record the event 2ND_FACTOR_REMOVED in the audit DB
	c.reportEvent(ctx, "2ND_FACTOR_REMOVED", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

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

	c.reportEvent(ctx, "LOGIN_FAILURE_CLEARED", database.CtEventRealmName, realmName, database.CtEventUserID, userID)

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
	roleKc, err := c.keycloakClient.GetRole(accessToken, realmName, roleID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return api.RoleRepresentation{}, err
	}

	if !c.isBusinessRole(roleKc) {
		return api.RoleRepresentation{}, errorhandler.CreateNotFoundError(prmRoleID)
	}

	roleRep.ID = roleKc.ID
	roleRep.Name = roleKc.Name
	roleRep.Composite = roleKc.Composite
	roleRep.ClientRole = roleKc.ClientRole
	roleRep.ContainerID = roleKc.ContainerID
	roleRep.Description = roleKc.Description

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
	c.reportEvent(ctx, "API_ROLE_CREATION", database.CtEventRealmName, realmName, database.CtEventRoleID, roleID, database.CtEventRoleName, *role.Name)

	return locationURL, nil
}

func (c *component) DeleteRole(ctx context.Context, realmName string, roleID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	role, err := c.keycloakClient.GetRole(accessToken, realmName, roleID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	if !c.isBusinessRole(role) {
		return errorhandler.CreateNotFoundError(prmRoleID)
	}

	err = c.keycloakClient.DeleteRole(accessToken, realmName, roleID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	var roleName = *role.Name
	//store the API call into the DB
	c.reportEvent(ctx, "API_ROLE_DELETION", database.CtEventRealmName, realmName, database.CtEventRoleName, roleName)

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
	c.reportEvent(ctx, "API_GROUP_CREATION", database.CtEventRealmName, realmName, database.CtEventGroupID, groupID, database.CtEventGroupName, *group.Name)

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
	c.reportEvent(ctx, "API_GROUP_DELETION", database.CtEventRealmName, realmName, database.CtEventGroupName, groupName)

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
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	var groupName = *group.Name

	authorizations := api.ConvertToDBAuthorizations(realmName, groupName, auth)

	if err = c.checkAllowedTargetRealmsAndGroupNames(ctx, realmName, authorizations); err != nil {
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

		err = c.configDBModule.DeleteAuthorizations(ctx, realmName, groupName)
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}

		for _, authorisation := range authorizations {
			err = c.configDBModule.CreateAuthorization(ctx, authorisation)
			if err != nil {
				c.logger.Warn(ctx, "err", err.Error())
				return err
			}
		}

		err = tx.Commit()
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}
	}

	c.reportEvent(ctx, "API_AUTHORIZATIONS_UPDATE", database.CtEventRealmName, realmName, database.CtEventGroupName, groupName)

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

	for _, action := range actions {
		var name = action.Name
		var scope = string(action.Scope)

		apiActions = append(apiActions, api.ActionRepresentation{
			Name:  &name,
			Scope: &scope,
		})
	}
	// The communications API is published internally only.
	// To be able to configure the rights from the BO we add them here.
	var sendMailName = "COM_SendEmail"
	var sendMailScope = string(security.ScopeRealm)
	var sendSMSName = "COM_SendSMS"
	var sendSMSScope = string(security.ScopeRealm)
	var deleteDeniedToUUsersName = "TSK_DeleteDeniedToUUsers"
	var deleteDeniedToUUsersScope = string(security.ScopeGlobal)
	apiActions = append(apiActions, api.ActionRepresentation{
		Name:  &sendMailName,
		Scope: &sendMailScope,
	})
	apiActions = append(apiActions, api.ActionRepresentation{
		Name:  &sendSMSName,
		Scope: &sendSMSScope,
	})
	apiActions = append(apiActions, api.ActionRepresentation{
		Name:  &deleteDeniedToUUsersName,
		Scope: &deleteDeniedToUUsersScope,
	})

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
		RedirectCancelledRegistrationURL:    customConfig.RedirectCancelledRegistrationURL,
		RedirectSuccessfulRegistrationURL:   customConfig.RedirectSuccessfulRegistrationURL,
		OnboardingRedirectURI:               customConfig.OnboardingRedirectURI,
		OnboardingClientID:                  customConfig.OnboardingClientID,
		SelfRegisterGroupNames:              customConfig.SelfRegisterGroupNames,
		BarcodeType:                         customConfig.BarcodeType,
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

func (c *component) GetRealmBackOfficeConfiguration(ctx context.Context, realmID string, groupName string) (api.BackOfficeConfiguration, error) {
	var dbResult, err = c.configDBModule.GetBackOfficeConfiguration(ctx, realmID, []string{groupName})
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

func (c *component) LinkShadowUser(ctx context.Context, realmName string, userID string, provider string, fedID api.FederatedIdentityRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var fedIDKC = api.ConvertToKCFedID(fedID)

	err := c.keycloakClient.LinkShadowUser(accessToken, realmName, userID, provider, fedIDKC)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	return nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
