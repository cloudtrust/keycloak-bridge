package management

import (
	"testing"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	var realmName = "DEP"
	var action1 = "action1"
	var action2 = "action2"
	var unknown = "unknown"
	var groupName1 = "groupName1"
	var groupName2 = "groupName2"
	var star = "*"

	var allowedTargetRealmsAndGroupNames = make(map[string]map[string]struct{})
	allowedTargetRealmsAndGroupNames["*"] = make(map[string]struct{})
	allowedTargetRealmsAndGroupNames["*"]["*"] = struct{}{}
	allowedTargetRealmsAndGroupNames[realmName] = make(map[string]struct{})
	allowedTargetRealmsAndGroupNames[realmName][groupName1] = struct{}{}
	allowedTargetRealmsAndGroupNames[realmName][groupName2] = struct{}{}
	allowedTargetRealmsAndGroupNames[realmName]["*"] = struct{}{}

	var authorizations = []configuration.Authorization{}

	// Invalid targetRealm
	{
		authorizations = []configuration.Authorization{
			configuration.Authorization{
				RealmID:       &realmName,
				GroupName:     &groupName1,
				Action:        &action2,
				TargetRealmID: &unknown,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	}

	// Invalid targetGroupName
	{
		authorizations = []configuration.Authorization{
			configuration.Authorization{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &unknown,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	}

	// Incompatible rules due to * in targetRealm
	{
		authorizations = []configuration.Authorization{
			configuration.Authorization{
				RealmID:       &realmName,
				GroupName:     &groupName1,
				Action:        &action2,
				TargetRealmID: &star,
			},
			configuration.Authorization{
				RealmID:       &realmName,
				GroupName:     &groupName1,
				Action:        &action2,
				TargetRealmID: &realmName,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	}

	// Incompatible rules due to * in targetGroupName
	{
		authorizations = []configuration.Authorization{
			configuration.Authorization{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
			configuration.Authorization{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &groupName1,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	}

	// Valid set of authorizations
	{
		authorizations = []configuration.Authorization{
			configuration.Authorization{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
			configuration.Authorization{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action1,
				TargetRealmID:   &star,
				TargetGroupName: &star,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.Nil(t, err)
	}
}
