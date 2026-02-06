package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
)

// KeycloakIdpClient interface exposes methods we need to call to send requests to Keycloak identity providers API
type KeycloakIdpClient interface {
	// Groups
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	// Role mappings
	GetRealmLevelRoleMappings(accessToken string, realmName, userID string) ([]kc.RoleRepresentation, error)
	// Users
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	DeleteUser(accessToken string, realmName, userID string) error
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
	// IDP
	GetIdp(accessToken string, realmName string, idpAlias string) (kc.IdentityProviderRepresentation, error)
	CreateIdp(accessToken string, realmName string, idpRep kc.IdentityProviderRepresentation) error
	UpdateIdp(accessToken string, realmName, idpAlias string, idpRep kc.IdentityProviderRepresentation) error
	DeleteIdp(accessToken string, realmName string, idpAlias string) error
	GetFederatedIdentities(accessToken string, realmName string, userID string) ([]kc.FederatedIdentityRepresentation, error)
	// Components
	GetComponents(accessToken string, realmName string, paramKV ...string) ([]kc.ComponentRepresentation, error)
	CreateComponent(accessToken string, realmName string, comp kc.ComponentRepresentation) error
	UpdateComponent(accessToken string, realmName, compID string, comp kc.ComponentRepresentation) error
	// IDP mappers
	GetIdpMappers(accessToken string, realmName string, idpAlias string) ([]kc.IdentityProviderMapperRepresentation, error)
	CreateIdpMapper(accessToken string, realmName string, idpAlias string, mapperRep kc.IdentityProviderMapperRepresentation) error
	UpdateIdpMapper(accessToken string, realmName string, idpAlias string, mapperID string, mapperRep kc.IdentityProviderMapperRepresentation) error
	DeleteIdpMapper(accessToken string, realmName string, idpAlias string, mapperID string) error
}

// Component interface exposes methods used by the bridge API
type Component interface {
	GetIdentityProvider(ctx context.Context, realmName string, providerAlias string) (api.IdentityProviderRepresentation, error)
	CreateIdentityProvider(ctx context.Context, realmName string, provider api.IdentityProviderRepresentation) error
	UpdateIdentityProvider(ctx context.Context, realmName string, providerAlias string, provider api.IdentityProviderRepresentation) error
	DeleteIdentityProvider(ctx context.Context, realmName string, providerAlias string) error
	GetIdentityProviderMappers(ctx context.Context, realmName string, idpAlias string) ([]api.IdentityProviderMapperRepresentation, error)
	CreateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, apiMapper api.IdentityProviderMapperRepresentation) error
	UpdateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string, apiMapper api.IdentityProviderMapperRepresentation) error
	DeleteIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string) error
	GetUsersWithAttribute(ctx context.Context, realmName string, username *string, groupName *string, expectedAttributes map[string]string, needRoles *bool) ([]api.UserRepresentation, error)
	GetUser(ctx context.Context, realmName string, userID string, groupName string) (api.UserRepresentation, error)
	DeleteUser(ctx context.Context, realmName string, userID string, groupName *string) error
	AddUserAttributes(ctx context.Context, realmName string, userID string, attributes map[string][]string) error
	DeleteUserAttributes(ctx context.Context, realmName string, userID string, attributeKeys []string) error
	GetUserFederatedIdentities(ctx context.Context, realmName string, userID string) ([]api.FederatedIdentityRepresentation, error)
}

type component struct {
	keycloakIdpClient KeycloakIdpClient
	tokenProvider     toolbox.OidcTokenProvider
	hrdTool           toolbox.ComponentTool
	logger            internal.Logger
}

// NewComponent returns the communications component.
func NewComponent(keycloakIdpClient KeycloakIdpClient, tokenProvider toolbox.OidcTokenProvider, hrdTool toolbox.ComponentTool, logger internal.Logger) Component {
	return &component{
		keycloakIdpClient: keycloakIdpClient,
		tokenProvider:     tokenProvider,
		hrdTool:           hrdTool,
		logger:            logger,
	}
}

func handleKeycloakIdpError(err error) error {
	return handleKeycloakError(err, "idp")
}

func handleKeycloakError(err error, messageKey string) error {
	if err != nil {
		switch e := err.(type) {
		case kc.HTTPError:
			if e.HTTPStatus == http.StatusNotFound {
				return errorhandler.CreateNotFoundError(messageKey)
			}
		case kc.ClientDetailedError:
			if e.Status() == http.StatusBadRequest {
				return errorhandler.CreateBadRequestError(messageKey)
			}
		default:
			return err
		}
	}
	return nil
}

func overrideKeycloakError(err error, messageKey string) error {
	var overridedErr = handleKeycloakError(err, messageKey)
	if overridedErr != nil {
		return overridedErr
	}
	return err
}

func (c *component) GetIdentityProvider(ctx context.Context, realmName string, idpAlias string) (api.IdentityProviderRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return api.IdentityProviderRepresentation{}, err
	}

	idp, err := c.keycloakIdpClient.GetIdp(accessToken, realmName, idpAlias)
	if err := handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get identity provider from keycloak", "err", err.Error(), "realm", realmName, "idp", idpAlias)
		return api.IdentityProviderRepresentation{}, err
	}

	return api.ConvertToAPIIdentityProvider(idp), nil
}

func (c *component) CreateIdentityProvider(ctx context.Context, realmName string, idp api.IdentityProviderRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	kcIdp := idp.ConvertToKCIdentityProvider()
	err = c.keycloakIdpClient.CreateIdp(accessToken, realmName, kcIdp)
	if err != nil {
		return err
	}

	if idp.HrdSettings != nil {
		if err = c.updateHrdConfig(ctx, accessToken, realmName, idp); err != nil {
			c.logger.Warn(ctx, "msg", "Can't update HRD configuration", "realm", realmName, "idp", *idp.Alias, "err", err.Error())
			return err
		}
	}

	return nil
}

func (c *component) UpdateIdentityProvider(ctx context.Context, realmName string, idpAlias string, idp api.IdentityProviderRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	kcIdp := idp.ConvertToKCIdentityProvider()
	err = c.keycloakIdpClient.UpdateIdp(accessToken, realmName, idpAlias, kcIdp)
	if err = handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update identity provider from keycloak", "err", err.Error(), "realm", realmName, "idp", idpAlias)
		return err
	}

	if idp.HrdSettings != nil {
		if err = c.updateHrdConfig(ctx, accessToken, realmName, idp); err != nil {
			c.logger.Warn(ctx, "msg", "Can't update HRD configuration", "realm", realmName, "idp", *idp.Alias, "err", err.Error())
			return err
		}
	}

	return nil
}

func (c *component) DeleteIdentityProvider(ctx context.Context, realmName string, idpAlias string) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	err = c.keycloakIdpClient.DeleteIdp(accessToken, realmName, idpAlias)
	if err = handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to delete identity provider from keycloak", "err", err.Error(), "realm", realmName, "idp", idpAlias)
		return err
	}

	if err = c.deleteHrdConfigKeyValue(ctx, accessToken, realmName, idpAlias); err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete HRD configuration", "realm", realmName, "idp", idpAlias, "err", err.Error())
		return err
	}

	return nil
}

func (c *component) findHrdComponent(ctx context.Context, accessToken string, realmName string) (*kc.ComponentRepresentation, error) {
	var additionalParams = []string{}
	additionalParams = append(additionalParams, "type", c.hrdTool.GetProviderType())
	comps, err := c.keycloakIdpClient.GetComponents(accessToken, realmName, additionalParams...)
	if err := handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get components from keycloak", "err", err.Error(), "realm", realmName)
		return nil, err
	}

	if len(comps) == 0 {
		return nil, nil
	}

	return c.hrdTool.FindComponent(comps), nil

}

func (c *component) updateHrdConfig(ctx context.Context, accessToken string, realmName string, idp api.IdentityProviderRepresentation) error {

	hrdComp, err := c.findHrdComponent(ctx, accessToken, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get component", "realm", realmName, "err", err.Error())
		return err
	}

	if hrdComp != nil {
		// The component already exists => Update it

		var settings api.HrdSettingModel
		if err = c.hrdTool.GetComponentEntry(hrdComp, *idp.Alias, &settings); err != nil {
			if errors.Is(err, toolbox.ErrConfigKeyNotFound) {
				settings = api.HrdSettingModel{}
			} else {
				c.logger.Warn(ctx, "msg", "Can't get component entry", "realm", realmName, "idp", idp.Alias, "err", err.Error())
				return err
			}
		}

		settings.IPRangesList = idp.HrdSettings.IPRangesList
		settings.Priority = idp.HrdSettings.Priority
		settings.DomainsList = idp.HrdSettings.DomainsList

		if err = c.hrdTool.UpdateComponentEntry(hrdComp, *idp.Alias, settings); err != nil {
			c.logger.Warn(ctx, "msg", "Can't update component entry", "realm", realmName, "idp", idp.Alias, "err", err.Error())
			return err
		}

		if err = c.keycloakIdpClient.UpdateComponent(accessToken, realmName, *hrdComp.ID, *hrdComp); err != nil {
			c.logger.Warn(ctx, "msg", "Can't update component on Keycloak", "realm", realmName, "component", *hrdComp.ID, "err", err.Error())
			return err
		}

	} else {
		// The component does not exist yet

		comp, err := c.hrdTool.InitializeComponent(realmName, *idp.Alias, idp.HrdSettings)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't initialize component", "realm", realmName, "idp", idp.Alias, "err", err.Error())
			return err
		}

		if err = c.keycloakIdpClient.CreateComponent(accessToken, realmName, comp); err != nil {
			c.logger.Warn(ctx, "msg", "Can't create component in Keycloak", "realm", realmName, "idp", idp.Alias, "err", err.Error())
			return err
		}
	}

	return nil
}

func (c *component) deleteHrdConfigKeyValue(ctx context.Context, accessToken string, realmName string, idpAlias string) error {

	comp, err := c.findHrdComponent(ctx, accessToken, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get component", "realm", realmName, "err", err.Error())
		return err
	}

	if comp == nil {
		return nil
	}

	deleted, err := c.hrdTool.DeleteComponentEntry(comp, idpAlias)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete entry", "realm", realmName, "idp", idpAlias, "err", err.Error())
		return fmt.Errorf("failed to delete component entry: %w", err)
	}
	if !deleted {
		// nothing to delete
		return nil
	}

	if err = c.keycloakIdpClient.UpdateComponent(accessToken, realmName, *comp.ID, *comp); err != nil {
		c.logger.Warn(ctx, "msg", "Can't update component", "realm", realmName, "idp", idpAlias, "err", err.Error())
		return err
	}

	return nil
}

func (c *component) GetIdentityProviderMappers(ctx context.Context, realmName string, idpAlias string) ([]api.IdentityProviderMapperRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return []api.IdentityProviderMapperRepresentation{}, err
	}

	kcMappers, err := c.keycloakIdpClient.GetIdpMappers(accessToken, realmName, idpAlias)
	if err = handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get idp mappers from keycloak", "err", err.Error(), "realm", realmName, "idp", idpAlias)
		return []api.IdentityProviderMapperRepresentation{}, err
	}

	return api.ConvertToAPIIdentityProviderMappers(kcMappers), nil
}

func (c *component) CreateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, apiMapper api.IdentityProviderMapperRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	kcMapper := apiMapper.ConvertToKCIdentityProviderMapper()
	err = c.keycloakIdpClient.CreateIdpMapper(accessToken, realmName, idpAlias, kcMapper)
	if err = handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to create idp mapper from keycloak", "err", err.Error(), "realm", realmName, "idp", idpAlias, "mapper", *kcMapper.IdentityProviderMapper)
		return err
	}

	return nil
}

func (c *component) UpdateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string, apiMapper api.IdentityProviderMapperRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	kcMapper := apiMapper.ConvertToKCIdentityProviderMapper()
	err = c.keycloakIdpClient.UpdateIdpMapper(accessToken, realmName, idpAlias, mapperID, kcMapper)
	if err = handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update idp mapper from keycloak", "err", err.Error(), "realm", realmName, "idp", idpAlias, "mapper", *kcMapper.IdentityProviderMapper)
		return err
	}

	return nil
}

func (c *component) DeleteIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	err = c.keycloakIdpClient.DeleteIdpMapper(accessToken, realmName, idpAlias, mapperID)
	if err = handleKeycloakIdpError(err); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to delete idp mapper from keycloak", "err", err.Error())
		return err
	}

	return nil
}

func (c *component) GetUser(ctx context.Context, realmName string, userID string, groupName string) (api.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return api.UserRepresentation{}, err
	}
	user, err := c.keycloakIdpClient.GetUser(accessToken, realmName, userID)
	if err = handleKeycloakError(err, "user"); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get user from keycloak", "err", err.Error(), "realm", realmName, "user", userID)
		return api.UserRepresentation{}, err
	}
	// Get groups of the user
	groups, err := c.keycloakIdpClient.GetGroupsOfUser(accessToken, realmName, userID)
	if err = handleKeycloakError(err, "user.groups"); err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get user groups from keycloak", "err", err.Error(), "realm", realmName, "user", userID)
		return api.UserRepresentation{}, err
	}
	var userGroups []string
	for _, group := range groups {
		userGroups = append(userGroups, *group.Name)
	}
	// Note that groups are copied to user representation from Keycloak but they are not part of the API structure
	// It can be easily added if needed in the future just by updating api package
	user.Groups = &userGroups
	// Check if the user is in the expected group
	if user.Groups == nil || !slices.Contains(*user.Groups, groupName) {
		c.logger.Warn(ctx, "msg", "User is not in the expected group", "realm", realmName, "user", userID, "group", groupName)
		return api.UserRepresentation{}, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + ".group")
	}

	return api.ConvertToAPIUserRepresentation(user), nil
}

func (c *component) DeleteUser(ctx context.Context, realmName string, userID string, groupName *string) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	// If groupName is provided, first check the user is in the given group
	if groupName != nil {
		err := c.checkUserIsInGroup(ctx, accessToken, realmName, userID, *groupName)
		if err != nil {
			return err
		}
	}

	err = c.keycloakIdpClient.DeleteUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get user from keycloak", "err", err.Error(), "realm", realmName, "user", userID)
		return err
	}

	return nil
}

func (c *component) checkUserIsInGroup(ctx context.Context, accessToken string, realmName string, userID string, groupName string) error {
	expectedGroup, err := c.getGroup(ctx, accessToken, realmName, groupName)
	if err != nil {
		return err
	}
	groups, err := c.keycloakIdpClient.GetGroupsOfUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get user groups from keycloak", "err", err.Error(), "realm", realmName, "user", userID)
		return handleKeycloakError(err, "user")
	}
	for _, group := range groups {
		if *group.ID == *expectedGroup.ID {
			return nil
		}
	}
	return errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + ".group")
}

func (c *component) getGroup(ctx context.Context, accessToken string, realmName string, groupName string) (*kc.GroupRepresentation, error) {
	var groups []kc.GroupRepresentation
	var err error
	if groups, err = c.keycloakIdpClient.GetGroups(accessToken, realmName); err != nil {
		c.logger.Warn(ctx, "msg", "Keycloak failed to get groups", "err", err.Error())
		return nil, err
	}
	for _, group := range groups {
		if *group.Name == groupName {
			return &group, nil
		}
	}
	return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + ".group")
}

func (c *component) GetUsersWithAttribute(ctx context.Context, realmName string, username *string, groupName *string, expectedAttributes map[string]string, needRoles *bool) ([]api.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return nil, err
	}

	var paramKV = []string{}

	if username != nil {
		paramKV = append(paramKV, "username", *username)
	}

	if groupName != nil {
		group, err := c.getGroup(ctx, accessToken, realmName, *groupName)
		if err != nil {
			return nil, err
		}
		paramKV = append(paramKV, "groupId", *group.ID)
	}

	if len(expectedAttributes) > 0 {
		// Compute query to search for custom attributes, in the format 'key1:value2 key2:value2'
		queryAttribute := []string{}
		for attributeKey, attributeValue := range expectedAttributes {
			queryAttribute = append(queryAttribute, fmt.Sprintf("%s:%s", attributeKey, attributeValue))
		}
		paramKV = append(paramKV, "q", strings.Join(queryAttribute, " "))
	}

	usersPage, err := c.keycloakIdpClient.GetUsers(accessToken, realmName, realmName, paramKV...)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Keycloak failed to search users", "err", err.Error(), "realm", realmName)
		return nil, err
	}
	if usersPage.Count == nil || *usersPage.Count == 0 || usersPage.Users == nil || len(usersPage.Users) == 0 {
		var res = make([]api.UserRepresentation, 0)
		return res, nil
	}

	if needRoles != nil && *needRoles {
		for idx, user := range usersPage.Users {
			roles, err := c.keycloakIdpClient.GetRealmLevelRoleMappings(accessToken, realmName, *user.ID)
			if err != nil {
				c.logger.Warn(ctx, "msg", "Keycloak failed to get user roles", "err", err.Error(), "realm", realmName, "user", *user.ID)
				return nil, err
			}
			var roleNames []string
			for _, role := range roles {
				roleNames = append(roleNames, *role.Name)
			}
			usersPage.Users[idx].RealmRoles = &roleNames
		}
	}

	return api.ConvertToAPIUserRepresentations(usersPage.Users), nil
}

func (c *component) AddUserAttributes(ctx context.Context, realmName string, userID string, attributes map[string][]string) error {
	// For now, we don't check which attributes are allowed to be set. If needed, we should use UserProfile feature and
	// check if annotations tell that the attribute is writable or not for the given interface.
	return c.updateUser(ctx, realmName, userID, func(user *kc.UserRepresentation) bool {
		var updated = false
		for attributeKey, attributeValues := range attributes {
			if c.addUserAttribute(ctx, user, attributeKey, attributeValues) {
				updated = true
			}
		}
		return updated
	})
}

func (c *component) addUserAttribute(_ context.Context, user *kc.UserRepresentation, attributeKey string, attributeValues []string) bool {
	var key = kc.AttributeKey(attributeKey)
	if user.Attributes == nil {
		var attributes = make(kc.Attributes)
		attributes.Set(key, attributeValues)
		user.Attributes = &attributes
		return true // Newly added
	}
	var current = user.Attributes.Get(key)
	if current == nil || !slices.Equal(current, attributeValues) {
		user.Attributes.Set(key, attributeValues)
		return true // Updated attribute
	}
	return false // No need to update. Attribute already has the expected value
}

func (c *component) DeleteUserAttributes(ctx context.Context, realmName string, userID string, attributeKeys []string) error {
	// For now, we don't check which attributes are allowed to be removed. If needed, we should use UserProfile feature and
	// check if annotations tell that the attribute is writable or not for the given interface.
	return c.updateUser(ctx, realmName, userID, func(user *kc.UserRepresentation) bool {
		var count = 0
		for _, attributeKey := range attributeKeys {
			var key = kc.AttributeKey(attributeKey)
			if user.Attributes != nil {
				var value = user.Attributes.GetString(key)
				if value != nil && *value != "" {
					user.Attributes.Remove(key)
					count++
				}
			}
		}
		return count > 0
	})
}

func (c *component) updateUser(ctx context.Context, realmName string, userID string, updateFunc func(user *kc.UserRepresentation) bool) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}
	user, err := c.keycloakIdpClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get Keycloak user", "err", err.Error(), "realm", realmName, "user", userID)
		return err
	}
	if updateFunc(&user) {
		err = overrideKeycloakError(c.keycloakIdpClient.UpdateUser(accessToken, realmName, userID, user), "attribute")
		if err != nil {
			c.logger.Warn(ctx, "msg", "Failed to update user from keycloak", "err", err.Error(), "realm", realmName, "user", userID)
			return err
		}
	}
	return nil
}

func (c *component) GetUserFederatedIdentities(ctx context.Context, realmName string, userID string) ([]api.FederatedIdentityRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return nil, err
	}

	kcFedIdentities, err := c.keycloakIdpClient.GetFederatedIdentities(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Keycloak failed to get federated identities", "err", err.Error(), "realm", realmName, "user", userID)
		return nil, err
	}

	var federatedIdentities []api.FederatedIdentityRepresentation
	for _, kcFedIdentity := range kcFedIdentities {
		federatedIdentities = append(federatedIdentities, api.FederatedIdentityRepresentation{
			UserID:           kcFedIdentity.UserID,
			Username:         kcFedIdentity.UserName,
			IdentityProvider: kcFedIdentity.IdentityProvider,
		})
	}
	return federatedIdentities, nil
}
