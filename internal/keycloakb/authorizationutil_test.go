package keycloakb

import (
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestTranslateGroupIDIntoGroupName(t *testing.T) {
	var realmName = "DEP"
	var action1 = "action1"
	var action2 = "action2"
	var groupID1 = "1111-646-54646"
	var groupID2 = "2222-646-54646"
	var unknownGroupID = "88888-646-54646"
	var groupName1 = "groupName1"
	var groupName2 = "groupName2"
	var star = "*"

	var origin = []dto.Authorization{
		dto.Authorization{
			RealmID: &realmName,
			GroupID: &groupID1,
			Action:  &action1,
		},
		dto.Authorization{
			RealmID:       &realmName,
			GroupID:       &groupID1,
			Action:        &action1,
			TargetRealmID: &star,
		},
		dto.Authorization{
			RealmID:       &realmName,
			GroupID:       &groupID1,
			Action:        &action2,
			TargetRealmID: &realmName,
		},
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
			TargetRealmID: &realmName,
			TargetGroupID: &groupID2,
		},
		dto.Authorization{
			RealmID:       &realmName,
			GroupID:       &groupID1,
			Action:        &action1,
			TargetRealmID: &realmName,
			TargetGroupID: &unknownGroupID,
		},
	}

	var groups = []kc.GroupRepresentation{
		kc.GroupRepresentation{
			Id:   &groupID1,
			Name: &groupName1,
		},
		kc.GroupRepresentation{
			Id:   &groupID2,
			Name: &groupName2,
		},
	}

	translated := TranslateGroupIDIntoGroupName(origin, groups)

	// Check the unknown one is removed
	assert.Equal(t, len(origin)-1, len(translated))

	for _, dtoAuthz := range translated {
		if dtoAuthz.TargetGroupID != nil {
			var targetGroupName = *dtoAuthz.TargetGroupID
			if targetGroupName != "*" && targetGroupName != groupName2 {
				assert.Fail(t, "Unexpected translated value")
			}
		}
	}

}

func TestTranslateGroupNameIntoGroupID(t *testing.T) {

	var realmName = "DEP"
	var action1 = "action1"
	var action2 = "action2"
	var groupID1 = "1111-646-54646"
	var groupID2 = "2222-646-54646"
	var unknownGroupName = "unknown"
	var groupName1 = "groupName1"
	var groupName2 = "groupName2"
	var star = "*"

	var origin = []dto.Authorization{
		dto.Authorization{
			RealmID: &realmName,
			GroupID: &groupID1,
			Action:  &action1,
		},
		dto.Authorization{
			RealmID:       &realmName,
			GroupID:       &groupID1,
			Action:        &action1,
			TargetRealmID: &star,
			TargetGroupID: &star,
		},
		dto.Authorization{
			RealmID:       &realmName,
			GroupID:       &groupID1,
			Action:        &action2,
			TargetRealmID: &realmName,
		},
		dto.Authorization{
			RealmID:       &realmName,
			GroupID:       &groupID1,
			Action:        &action1,
			TargetRealmID: &realmName,
			TargetGroupID: &groupName1,
		},
		dto.Authorization{
			RealmID:       &realmName,
			GroupID:       &groupID1,
			Action:        &action1,
			TargetRealmID: &realmName,
			TargetGroupID: &unknownGroupName,
		},
	}

	var mapper = make(map[string]map[string]string)
	mapper["*"] = make(map[string]string)
	mapper["*"]["*"] = "*"
	mapper[realmName] = make(map[string]string)
	mapper[realmName][groupName1] = groupID1
	mapper[realmName][groupName2] = groupID2
	mapper[realmName]["*"] = "*"

	translated := TranslateGroupNameIntoGroupID(origin, mapper)

	// Check the unkown is removed
	assert.Equal(t, len(origin)-1, len(translated))

	for _, dtoAuthz := range translated {
		if dtoAuthz.TargetGroupID != nil {
			var targetGroupID = *dtoAuthz.TargetGroupID
			if targetGroupID != "*" && targetGroupID != groupID2 && targetGroupID != groupID1 {
				assert.Fail(t, "Unexpected translated value "+targetGroupID)
			}
		}
	}
}

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
