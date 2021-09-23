package management

import (
	"errors"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
)

// Validate the content of the provided array. Returns an error if any issue is detected
func Validate(authorizations []configuration.Authorization, allowedTargetRealmsAndGroupNames map[string]map[string]struct{}) error {
	if err := checkTarget(authorizations, allowedTargetRealmsAndGroupNames); err != nil {
		return err
	}

	var authZ = api.ConvertToAPIAuthorizations(authorizations)

	var checker = *authZ.Matrix
	for _, u := range checker {
		for realmID, v := range u {
			// Check if * as targetRealm, there is no other targetRealm rule
			if realmID == "*" && len(u) != 1 {
				return errors.New("if '*' is used as targetRealm, no other rules for this action are allowed")
			}

			// Check if * as targetGroupName, there is no other targetGroupName rule
			for targetGroup := range v {
				if targetGroup == "*" && len(v) != 1 {
					return errors.New("if '*' is used as targetGroupName, no other rules are allowed")
				}
			}
		}
	}

	return nil
}

func checkTarget(authorizations []configuration.Authorization, allowedTargetRealmsAndGroupNames map[string]map[string]struct{}) error {
	for _, auth := range authorizations {
		// Check TargetRealm
		if auth.TargetRealmID != nil {
			if _, ok := allowedTargetRealmsAndGroupNames[*auth.TargetRealmID]; !ok {
				return errors.New("invalid target realm")
			}
		}

		// Check TargetGroupName
		if auth.TargetGroupName != nil {
			if _, ok := allowedTargetRealmsAndGroupNames[*auth.TargetRealmID][*auth.TargetGroupName]; !ok {
				return errors.New("invalid target group")
			}
		}
	}
	return nil
}

// Validate the scope of each authorization in the array. Returns an error if an authorization is not valid
func validateScopes(authorizations []configuration.Authorization) error {
	for _, authz := range authorizations {
		scope, err := getScope(authz)
		if err != nil {
			return err
		}

		if authz.TargetRealmID == nil {
			return errors.New("missing target realm")
		}

		switch scope {
		case security.ScopeGlobal:
			if *authz.TargetRealmID != "*" || authz.TargetGroupName != nil {
				return errors.New("invalid global scope")
			}
		case security.ScopeRealm:
			if authz.TargetGroupName == nil || *authz.TargetGroupName != "*" {
				return errors.New("invalid realm scope")
			}
		case security.ScopeGroup:
			if authz.TargetGroupName == nil {
				return errors.New("invalid group scope")
			}
		}
	}
	return nil
}

func getScope(authz configuration.Authorization) (security.Scope, error) {
	for _, action := range GetActions() {
		if *authz.Action == action.String() {
			return action.Scope, nil
		}
	}
	return "", errors.New("invalid action")
}
