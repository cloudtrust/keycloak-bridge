package management

import (
	"errors"

	"github.com/cloudtrust/common-service/v2/configuration"
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
