package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cs "github.com/cloudtrust/common-service"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/log"
)

func (am *authorizationManager) CheckAuthorizationOnTargetUser(ctx context.Context, action, targetRealm, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	bInfos, _ := json.Marshal(map[string]string{
		"ThrownBy":    "CheckAuthorizationOnTargetUser",
		"Action":      action,
		"targetRealm": targetRealm,
		"userID":      userID,
	})
	var infos = string(bInfos)

	// Retrieve the group of the target user

	var groupsRep []kc.GroupRepresentation
	var err error
	if groupsRep, err = am.keycloakClient.GetGroupsOfUser(accessToken, targetRealm, userID); err != nil {
		am.logger.Log("ForbiddenError", err.Error(),
			"infos", infos)

		return ForbiddenError{}
	}

	if groupsRep == nil || len(groupsRep) == 0 {
		am.logger.Log("ForbiddenError", "No groups assigned to this user, nothin allowed",
			"infos", infos)

		// No groups assigned, nothing allowed
		return ForbiddenError{}
	}

	for _, targetGroup := range groupsRep {
		if am.CheckAuthorizationOnTargetGroup(ctx, action, targetRealm, *targetGroup.Name) == nil {
			return nil
		}
	}

	am.logger.Log("ForbiddenError", "No allowed to perform the action on user with such groups",
		"infos", infos)

	return ForbiddenError{}
}

func (am *authorizationManager) CheckAuthorizationOnTargetGroupID(ctx context.Context, action, targetRealm, targetGroupID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	bInfos, _ := json.Marshal(map[string]string{
		"ThrownBy":      "CheckAuthorizationOnTargetGroupID",
		"Action":        action,
		"targetRealm":   targetRealm,
		"targetGroupID": targetGroupID,
	})
	var infos = string(bInfos)

	// Retrieve the name of the target group
	var err error
	var targetGroup kc.GroupRepresentation
	if targetGroup, err = am.keycloakClient.GetGroup(accessToken, targetRealm, targetGroupID); err != nil {
		am.logger.Log("ForbiddenError", err.Error(),
			"infos", infos)
		return ForbiddenError{}
	}

	if targetGroup.Name == nil || *(targetGroup.Name) == "" {
		am.logger.Log("ForbiddenError", "Group not found",
			"infos", infos)
		return ForbiddenError{}
	}

	return am.CheckAuthorizationOnTargetGroup(ctx, action, targetRealm, *(targetGroup.Name))
}

func (am *authorizationManager) CheckAuthorizationOnTargetGroup(ctx context.Context, action, targetRealm, targetGroup string) error {
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var currentGroups = ctx.Value(cs.CtContextGroups).([]string)

	bInfos, _ := json.Marshal(map[string]string{
		"ThrownBy":      "CheckAuthorizationOnTargetGroup",
		"Action":        action,
		"targetRealm":   targetRealm,
		"targetGroup":   targetGroup,
		"currentRealm":  currentRealm,
		"currentGroups": strings.Join(currentGroups, "|"),
	})
	var infos = string(bInfos)

	for _, group := range currentGroups {
		targetGroupAllowed, wildcard := am.authorizations[currentRealm][group][action]["*"]

		if wildcard {
			_, allGroupsAllowed := targetGroupAllowed["*"]
			_, groupAllowed := targetGroupAllowed[targetGroup]

			if allGroupsAllowed || groupAllowed {
				return nil
			}
		}

		targetGroupAllowed, nonMasterRealmAllowed := am.authorizations[currentRealm][group][action]["/"]

		if targetRealm != "master" && nonMasterRealmAllowed {
			_, allGroupsAllowed := targetGroupAllowed["*"]
			_, groupAllowed := targetGroupAllowed[targetGroup]

			if allGroupsAllowed || groupAllowed {
				return nil
			}
		}

		targetGroupAllowed, realmAllowed := am.authorizations[currentRealm][group][action][targetRealm]

		if realmAllowed {
			_, allGroupsAllowed := targetGroupAllowed["*"]
			_, groupAllowed := targetGroupAllowed[targetGroup]

			if allGroupsAllowed || groupAllowed {
				return nil
			}
		}
	}

	am.logger.Log("ForbiddenError", "Not allowed to perform the action on this group",
		"infos", infos)

	return ForbiddenError{}
}

func (am *authorizationManager) CheckAuthorizationOnTargetRealm(ctx context.Context, action, targetRealm string) error {
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var currentGroups = ctx.Value(cs.CtContextGroups).([]string)

	bInfos, _ := json.Marshal(map[string]string{
		"ThrownBy":      "CheckAuthorizationOnTargetRealm",
		"Action":        action,
		"targetRealm":   targetRealm,
		"currentRealm":  currentRealm,
		"currentGroups": strings.Join(currentGroups, "|"),
	})
	var infos = string(bInfos)

	for _, group := range currentGroups {
		_, wildcard := am.authorizations[currentRealm][group][action]["*"]
		_, nonMasterRealmAllowed := am.authorizations[currentRealm][group][action]["/"]
		_, realmAllowed := am.authorizations[currentRealm][group][action][targetRealm]

		if wildcard || realmAllowed || (targetRealm != "master" && nonMasterRealmAllowed) {
			return nil
		}
	}

	am.logger.Log("ForbiddenError", "Not allowed to perform the action on this realm",
		"infos", infos)

	return ForbiddenError{}
}

// ForbiddenError when an operation is not permitted.
type ForbiddenError struct{}

func (e ForbiddenError) Error() string {
	return "ForbiddenError: Operation not permitted"
}

// Authorizations data structure
// 4 dimensions table to express authorizations (realm_of_user, role_of_user, action, target_realm) -> target_group for which the action is allowed
type authorizations map[string]map[string]map[string]map[string]map[string]struct{}

// LoadAuthorizations loads the authorization JSON into the data structure
// Authorization matrix is a 4 dimensions table :
//   - realm_of_user
//   - role_of_user
//   - action
//   - target_realm
// -> target_groups for which the action is allowed
//
// Note:
//   '*' can be used to express all target realms
//   '/' can be used to express all non master realms
//   '*' can be used to express all target groups are allowed
func loadAuthorizations(jsonAuthz string) (authorizations, error) {
	if jsonAuthz == "" {
		return nil, fmt.Errorf("JSON structure expected")
	}
	var authz = make(authorizations)

	if err := json.Unmarshal([]byte(jsonAuthz), &authz); err != nil {
		return nil, err
	}

	return authz, nil
}

type authorizationManager struct {
	authorizations authorizations
	keycloakClient KeycloakClient
	logger         log.Logger
}

// KeycloakClient is the minimum interface required to access Keycloak
type KeycloakClient interface {
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
	GetGroup(accessToken string, realmName, groupID string) (kc.GroupRepresentation, error)
}

// AuthorizationManager interface
type AuthorizationManager interface {
	CheckAuthorizationOnTargetRealm(ctx context.Context, action, targetRealm string) error
	CheckAuthorizationOnTargetGroup(ctx context.Context, action, targetRealm, targetGroup string) error
	CheckAuthorizationOnTargetGroupID(ctx context.Context, action, targetRealm, targetGroupID string) error
	CheckAuthorizationOnTargetUser(ctx context.Context, action, targetRealm, userID string) error
}

// Authorizations data structure

// NewAuthorizationManager loads the authorization JSON into the data structure and create an AuthorizationManager instance.
// Authorization matrix is a 4 dimensions table :
//   - realm_of_user
//   - role_of_user
//   - action
//   - target_realm
// -> target_groups for which the action is allowed
//
// Note:
//   '*' can be used to express all target realms
//   '/' can be used to express all non master realms
//   '*' can be used to express all target groups are allowed
func NewAuthorizationManager(keycloakClient KeycloakClient, logger log.Logger, jsonAuthz string) (AuthorizationManager, error) {
	matrix, err := loadAuthorizations(jsonAuthz)

	if err != nil {
		return nil, err
	}

	return &authorizationManager{
		authorizations: matrix,
		keycloakClient: keycloakClient,
		logger:         logger,
	}, nil
}
