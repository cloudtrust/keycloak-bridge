package dto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertToAuthorizations(t *testing.T) {

	var jsonAuthz = `{
					"GetRealms": {},
					"GetRealm": {"*": {} },
					"GetClient": {"*": {"*": {} }},
					"GetClients": {"*": {"*": {} }},
					"GetRequiredActions": {"*": {"*": {} }},
					"DeleteUser": {"*": {"*": {} }},
					"GetUser": {"*": {"*": {} }},
					"UpdateUser": {"*": {"*": {} }},
					"GetUsers": {"*": {"*": {} }},
					"CreateUser": {"*": {"*": {} }},
					"GetUserAccountStatus": {"*": {"*": {} }},
					"GetRolesOfUser": {"*": {"*": {} }},
					"GetGroupsOfUser": {"*": {"*": {} }},
					"GetClientRolesForUser": {"*": {"*": {} }},
					"AddClientRolesToUser": {"*": {"*": {} }},
					"ResetPassword": {"*": {"*": {} }},
					"ExecuteActionsEmail": {"*": {"*": {} }},
					"SendNewEnrolmentCode": {"*": {"*": {} }},
					"SendReminderEmail": {"*": {"*": {} }},
					"ResetSmsCounter": {"*": {"*": {} }},
					"CreateRecoveryCode": {"*": {"*": {} }},
					"GetCredentialsForUser": {"*": {"*": {} }},
					"DeleteCredentialsForUser": {"*": {"*": {} }},
					"GetRoles": {"*": {"*": {} }},
					"GetRole": {"*": {"*": {} }},
					"GetGroups": {"*": {"*": {} }},
					"GetClientRoles": {"*": {"*": {} }},
					"CreateClientRole": {"*": {"*": {} }},
					"GetRealmCustomConfiguration": {"*": {"*": {} }},
					"UpdateRealmCustomConfiguration": {"*": {"*": {} }}
		}`

	var authz = make(map[string]map[string]map[string]struct{})

	if err := json.Unmarshal([]byte(jsonAuthz), &authz); err != nil {
		assert.Fail(t, "")
	}

	authorizations := ConvertToAuthorizations("realmID", "groupID", authz)
	assert.Equal(t, "", authorizations)
}

func TestConvertAuthorizationsToMap(t *testing.T) {

	var master = "master"
	var groupID = "1234-54451-4545"
	var action = "action"
	var action2 = "action2"
	var any = "*"

	var authorizations = []Authorization{}

	var authz1 = Authorization{
		RealmID:       &master,
		GroupID:       &groupID,
		Action:        &action,
		TargetRealmID: &master,
		TargetGroupID: &groupID,
	}

	var authz2 = Authorization{
		RealmID:       &master,
		GroupID:       &groupID,
		Action:        &action2,
		TargetRealmID: &any,
	}

	authorizations = append(authorizations, authz1)
	authorizations = append(authorizations, authz2)

	var matrix = ConvertToMap(authorizations)

	_, ok := matrix[action][master][groupID]
	assert.Equal(t, true, ok)

	_, ok = matrix[action][master][master]
	assert.Equal(t, false, ok)

	_, ok = matrix[action2][any]
	assert.Equal(t, true, ok)

}
