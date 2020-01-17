package keycloakb

import (
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	var realmName = "DEP"
	var action1 = "action1"
	var action2 = "action2"
	var groupID1 = "1111-646-54646"
	var groupID2 = "2222-646-54646"
	var unknown = "unknown"
	var groupName1 = "groupName1"
	var groupName2 = "groupName2"
	var star = "*"

	var allowedTargetRealmsAndGroupIDs = make(map[string]map[string]string)
	allowedTargetRealmsAndGroupIDs["*"] = make(map[string]string)
	allowedTargetRealmsAndGroupIDs["*"]["*"] = "*"
	allowedTargetRealmsAndGroupIDs[realmName] = make(map[string]string)
	allowedTargetRealmsAndGroupIDs[realmName][groupID1] = groupName1
	allowedTargetRealmsAndGroupIDs[realmName][groupID2] = groupName2
	allowedTargetRealmsAndGroupIDs[realmName]["*"] = "*"

	var authorizations = []dto.Authorization{}

	// Invalid targetRealm
	{
		authorizations = []dto.Authorization{
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action2,
				TargetRealmID: &unknown,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupIDs)
		assert.NotNil(t, err)
	}

	// Invalid targetGroupID
	{
		authorizations = []dto.Authorization{
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action2,
				TargetRealmID: &realmName,
				TargetGroupID: &unknown,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupIDs)
		assert.NotNil(t, err)
	}

	// Incompatible rules due to * in targetRealm
	{
		authorizations = []dto.Authorization{
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action2,
				TargetRealmID: &star,
			},
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action2,
				TargetRealmID: &realmName,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupIDs)
		assert.NotNil(t, err)
	}

	// Incompatible rules due to * in targetGroupID
	{
		authorizations = []dto.Authorization{
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action2,
				TargetRealmID: &realmName,
				TargetGroupID: &star,
			},
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action2,
				TargetRealmID: &realmName,
				TargetGroupID: &groupID1,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupIDs)
		assert.NotNil(t, err)
	}

	// Valid set of authorizations
	{
		authorizations = []dto.Authorization{
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action2,
				TargetRealmID: &realmName,
				TargetGroupID: &star,
			},
			dto.Authorization{
				RealmID:       &realmName,
				GroupID:       &groupID1,
				Action:        &action1,
				TargetRealmID: &star,
				TargetGroupID: &star,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupIDs)
		assert.Nil(t, err)
	}
}
