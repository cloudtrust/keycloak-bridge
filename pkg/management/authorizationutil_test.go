package management

import (
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"
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

	var authorizations []configuration.Authorization

	t.Run("Invalid targetRealm", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:       &realmName,
				GroupName:     &groupName1,
				Action:        &action2,
				TargetRealmID: &unknown,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	})

	t.Run("Invalid targetGroupName", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &unknown,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	})

	t.Run("Incompatible rules due to * in targetRealm", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:       &realmName,
				GroupName:     &groupName1,
				Action:        &action2,
				TargetRealmID: &star,
			},
			{
				RealmID:       &realmName,
				GroupName:     &groupName1,
				Action:        &action2,
				TargetRealmID: &realmName,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	})

	t.Run("Incompatible rules due to * in targetGroupName", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &groupName1,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.NotNil(t, err)
	})

	t.Run("Valid set of authorizations", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action2,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &action1,
				TargetRealmID:   &star,
				TargetGroupName: &star,
			},
		}

		err := Validate(authorizations, allowedTargetRealmsAndGroupNames)
		assert.Nil(t, err)
	})
}

func TestValidateScope(t *testing.T) {
	var masterRealm = "master"
	var realmName = "DEP"
	var groupName1 = "groupName1"
	var star = "*"

	var actionGlobal = "MGMT_GetActions"
	var actionRealm = "MGMT_GetRealm"
	var actionGroup = "MGMT_DeleteUser"

	var authorizations []configuration.Authorization

	t.Run("Valid global scope", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &masterRealm,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &star,
				TargetGroupName: nil,
			},
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &realmName,
				TargetGroupName: nil,
			},
		}
		err := validateScopes(authorizations)
		assert.Nil(t, err)
	})

	t.Run("Valid realm scope", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionRealm,
				TargetRealmID:   &star,
				TargetGroupName: &star,
			},
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionRealm,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
		}
		err := validateScopes(authorizations)
		assert.Nil(t, err)
	})

	t.Run("Valid group scope", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGroup,
				TargetRealmID:   &star,
				TargetGroupName: &star,
			},
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGroup,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGroup,
				TargetRealmID:   &realmName,
				TargetGroupName: &groupName1,
			},
		}
		err := validateScopes(authorizations)
		assert.Nil(t, err)
	})

	t.Run("Invalid global scope", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &star,
				TargetGroupName: &star,
			},
		}
		err := validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
		}
		err = validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &realmName,
				TargetGroupName: &groupName1,
			},
		}
		err = validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &star,
				TargetGroupName: nil,
			},
		}
		err = validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &masterRealm,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &masterRealm,
				TargetGroupName: nil,
			},
		}
		err = validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &masterRealm,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &realmName,
				TargetGroupName: nil,
			},
		}
		err = validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())
	})

	t.Run("Invalid realm scope", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionRealm,
				TargetRealmID:   &realmName,
				TargetGroupName: &groupName1,
			},
		}
		err := validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionRealm,
				TargetRealmID:   &realmName,
				TargetGroupName: nil,
			},
		}
		err = validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())
	})

	t.Run("Invalid group scope", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGroup,
				TargetRealmID:   &star,
				TargetGroupName: nil,
			},
		}
		err := validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.scope", err.Error())
	})

	t.Run("Invalid action", func(t *testing.T) {
		invalidAction := "TestActionInvalid"
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &invalidAction,
				TargetRealmID:   &star,
				TargetGroupName: nil,
			},
		}
		err := validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .invalidParameter.authorization.action", err.Error())
	})

	t.Run("Missing target realm", func(t *testing.T) {
		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   nil,
				TargetGroupName: nil,
			},
		}
		err := validateScopes(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "400 .missingParameter.authorization.targetRealm", err.Error())
	})
}
