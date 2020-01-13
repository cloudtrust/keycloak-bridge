package dto

// Authorization struct
type Authorization struct {
	RealmID       *string `json:"realm_id"`
	GroupID       *string `json:"group_id"`
	Action        *string `json:"action"`
	TargetRealmID *string `json:"target_realm_id,omitempty"`
	TargetGroupID *string `json:"target_group_id,omitempty"`
}

func ConvertToMap(authorizations []Authorization) map[string]map[string]map[string]struct{} {
	var matrix = make(map[string]map[string]map[string]struct{})

	for _, authz := range authorizations {
		_, ok := matrix[*authz.Action]

		if !ok {
			matrix[*authz.Action] = make(map[string]map[string]struct{})
		}

		_, ok = matrix[*authz.Action][*authz.TargetRealmID]
		if !ok {
			matrix[*authz.Action][*authz.TargetRealmID] = make(map[string]struct{})
		}

		if authz.TargetRealmID == nil {
			break
		}

		_, ok = matrix[*authz.Action][*authz.TargetRealmID]
		if !ok {
			matrix[*authz.Action][*authz.TargetRealmID] = make(map[string]struct{})
		}

		if authz.TargetGroupID == nil {
			break
		}

		matrix[*authz.Action][*authz.TargetRealmID][*authz.TargetGroupID] = struct{}{}
	}

	return matrix
}

func ConvertToAuthorizations(realmID, groupID string, authorizationMap map[string]map[string]map[string]struct{}) []Authorization {

	var authorizations = []Authorization{}

	for action, u := range authorizationMap {

		if len(u) == 0 {
			var act = string(action)
			authorizations = append(authorizations, Authorization{
				RealmID: &realmID,
				GroupID: &groupID,
				Action:  &act,
			})
			continue
		}

		for targeteRealmID, v := range u {

			if len(v) == 0 {
				var act = string(action)
				var targetRealm = string(targeteRealmID)
				authorizations = append(authorizations, Authorization{
					RealmID:       &realmID,
					GroupID:       &groupID,
					Action:        &act,
					TargetRealmID: &targetRealm,
				})
				continue
			}

			for targetGroupID := range v {
				var act = string(action)
				var targetRealm = string(targeteRealmID)
				var targetGroup = string(targetGroupID)
				authorizations = append(authorizations, Authorization{
					RealmID:       &realmID,
					GroupID:       &groupID,
					Action:        &act,
					TargetRealmID: &targetRealm,
					TargetGroupID: &targetGroup,
				})
			}
		}
	}

	return authorizations
}
