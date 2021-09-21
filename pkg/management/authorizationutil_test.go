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
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &star,
				TargetGroupName: nil,
			},
		}
		err := ValidateScope(authorizations)
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
		err := ValidateScope(authorizations)
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
		err := ValidateScope(authorizations)
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
		err := ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid global scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &realmName,
				TargetGroupName: &star,
			},
		}
		err = ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid global scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionGlobal,
				TargetRealmID:   &realmName,
				TargetGroupName: &groupName1,
			},
		}
		err = ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid global scope", err.Error())
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
		err := ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid realm scope", err.Error())

		authorizations = []configuration.Authorization{
			{
				RealmID:         &realmName,
				GroupName:       &groupName1,
				Action:          &actionRealm,
				TargetRealmID:   &realmName,
				TargetGroupName: nil,
			},
		}
		err = ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid realm scope", err.Error())
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
		err := ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid group scope", err.Error())
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
		err := ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid action", err.Error())
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
		err := ValidateScope(authorizations)
		assert.NotNil(t, err)
		assert.Equal(t, "missing target realm", err.Error())
	})
}
