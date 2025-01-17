package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetActionsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetActionsEndpoint(mockManagementComponent)

	var ctx = context.Background()

	mockManagementComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil)
	var res, err = e(ctx, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetRealmsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmsEndpoint(mockManagementComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockManagementComponent.EXPECT().GetRealms(ctx).Return([]api.RealmRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetRealmEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetRealm(ctx, realm).Return(api.RealmRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetClientEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientEndpoint(mockManagementComponent)

	var realm = "master"
	var clientID = "1234-4567-7895"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmClientID] = clientID

	mockManagementComponent.EXPECT().GetClient(ctx, realm, clientID).Return(api.ClientRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetClientsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientsEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetClients(ctx, realm).Return([]api.ClientRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetRequiredActionsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRequiredActionsEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetRequiredActions(ctx, realm).Return([]api.RequiredActionRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestCreateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockProfileCache        = mock.NewUserProfileCache(mockCtrl)
		mockManagementComponent = mock.NewManagementComponent(mockCtrl)

		e = MakeCreateUserEndpoint(mockManagementComponent, mockProfileCache, log.NewNopLogger())

		realm       = "master"
		targetRealm = "targetRealm"
		location    = "https://location.url/auth/admin/master/users/123456"
		ctx         = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		groups      = []string{"f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"}
		anyError    = errors.New("any")
	)

	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		var req = map[string]string{
			prmRealm: targetRealm,
			reqBody:  "{}",
		}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, targetRealm).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	mockProfileCache.EXPECT().GetRealmUserProfile(ctx, targetRealm).Return(kc.UserProfileRepresentation{
		Attributes: []kc.ProfileAttrbRepresentation{
			{
				Name: ptr("gender"),
				Required: &kc.ProfileAttrbRequiredRepresentation{
					Roles: []string{"admin"},
				},
				Validations: kc.ProfileAttrbValidationRepresentation{
					"pattern": kc.ProfileAttrValidatorRepresentation{"pattern": `^[MF]$`},
				},
				Annotations: map[string]string{"bo": "true"},
			},
		},
	}, nil).AnyTimes()

	t.Run("No error", func(t *testing.T) {
		var user = api.UserRepresentation{Gender: ptr("M"), Groups: &groups}
		userJSON, _ := json.Marshal(user)
		var req = map[string]string{
			reqScheme: "https",
			reqHost:   "elca.ch",
			prmRealm:  targetRealm,
			reqBody:   string(userJSON),
		}

		mockManagementComponent.EXPECT().CreateUser(ctx, targetRealm, user, false, false, false).Return(location, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/users/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Invalid body", func(t *testing.T) {
		var req = map[string]string{
			prmRealm: targetRealm,
			reqBody:  `{}`,
		}
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Missing groups", func(t *testing.T) {
		var req = map[string]string{
			prmRealm: targetRealm,
		}
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: nil})
		req[reqBody] = string(userJSON)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = targetRealm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, targetRealm, gomock.Any(), false, false, false).Return("", fmt.Errorf("Error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Unparsable location", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = targetRealm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, targetRealm, api.UserRepresentation{Groups: &groups}, false, false, false).Return("/unrecognized/location", nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.IsType(t, LocationHeader{}, res)
		var hdr = res.(LocationHeader)
		assert.Equal(t, invalidLocation, hdr.URL)
	})
}

func TestCreateUserInSocialRealmEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockProfileCache        = mock.NewUserProfileCache(mockCtrl)
		mockManagementComponent = mock.NewManagementComponent(mockCtrl)

		e = MakeCreateUserInSocialRealmEndpoint(mockManagementComponent, mockProfileCache, socialRealmName, log.NewNopLogger())

		realm       = "master"
		targetRealm = "targetRealm"
		location    = "https://location.url/auth/admin/master/users/123456"
		ctx         = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		groups      = []string{"f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"}
		anyError    = errors.New("any")
	)

	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		var req = map[string]string{
			prmRealm: targetRealm,
			reqBody:  "{}",
		}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, socialRealmName).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	mockProfileCache.EXPECT().GetRealmUserProfile(ctx, socialRealmName).Return(kc.UserProfileRepresentation{
		Attributes: []kc.ProfileAttrbRepresentation{
			{
				Name: ptr("gender"),
				Required: &kc.ProfileAttrbRequiredRepresentation{
					Roles: []string{"admin"},
				},
				Validations: kc.ProfileAttrbValidationRepresentation{
					"pattern": kc.ProfileAttrValidatorRepresentation{"pattern": `^[MF]$`},
				},
				Annotations: map[string]string{"bo": "true"},
			},
		},
	}, nil).AnyTimes()

	t.Run("No error", func(t *testing.T) {
		var req = map[string]string{
			reqScheme: "https",
			reqHost:   "elca.ch",
			prmRealm:  targetRealm,
		}
		var user = api.UserRepresentation{Gender: ptr("M"), Groups: &groups}

		userJSON, _ := json.Marshal(user)
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUserInSocialRealm(ctx, user, false).Return(location, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/users/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = map[string]string{reqBody: "JSON"}
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Invalid body", func(t *testing.T) {
		var req = map[string]string{
			prmRealm: targetRealm,
			reqBody:  `{"email":""}`,
		}
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Missing groups", func(t *testing.T) {
		var req = map[string]string{
			prmRealm: targetRealm,
		}
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: nil})
		req[reqBody] = string(userJSON)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = targetRealm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUserInSocialRealm(ctx, gomock.Any(), false).Return("", fmt.Errorf("Error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Unparsable location", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = targetRealm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUserInSocialRealm(ctx, api.UserRepresentation{Groups: &groups}, false).Return("/unrecognized/location", nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.IsType(t, LocationHeader{}, res)
		var hdr = res.(LocationHeader)
		assert.Equal(t, invalidLocation, hdr.URL)
	})
}

func TestDeleteUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteUserEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().DeleteUser(ctx, realm, userID).Return(nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)
}

func TestGetUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().GetUser(ctx, realm, userID).Return(api.UserRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestUpdateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockProfileCache        = mock.NewUserProfileCache(mockCtrl)
		mockManagementComponent = mock.NewManagementComponent(mockCtrl)

		e = MakeUpdateUserEndpoint(mockManagementComponent, mockProfileCache, log.NewNopLogger())

		realm       = "the-realm"
		targetRealm = "targetRealm"
		userID      = "1234-452-4578"
		theUser     = api.UserRepresentation{Gender: ptr("M")}
		ctx         = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		anyError    = errors.New("any")
	)

	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		var req = map[string]string{
			prmRealm: targetRealm,
			reqBody:  "{}",
		}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, targetRealm).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	mockProfileCache.EXPECT().GetRealmUserProfile(ctx, targetRealm).Return(kc.UserProfileRepresentation{
		Attributes: []kc.ProfileAttrbRepresentation{
			{
				Name: ptr("gender"),
				Required: &kc.ProfileAttrbRequiredRepresentation{
					Roles: []string{"admin"},
				},
				Validations: kc.ProfileAttrbValidationRepresentation{
					"pattern": kc.ProfileAttrValidatorRepresentation{"pattern": `^[MF]$`},
				},
				Annotations: map[string]string{"bo": "true"},
			},
		},
	}, nil).AnyTimes()

	t.Run("No error", func(t *testing.T) {
		var req = make(map[string]string)
		req[prmRealm] = targetRealm
		req[prmUserID] = userID
		userJSON, _ := json.Marshal(theUser)
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().UpdateUser(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var req = make(map[string]string)
		req[prmRealm] = targetRealm
		req[prmUserID] = userID
		req[reqBody] = string("userJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestLockUserEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realm = "master"
	var userID = "1234-452-4578"
	var anyError = errors.New("any")
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("LockUser", func(t *testing.T) {
		var e = MakeLockUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().LockUser(ctx, realm, userID).Return(nil)
			var res, err = e(ctx, req)
			assert.Nil(t, err)
			assert.Nil(t, res)
		})
		t.Run("Error occured", func(t *testing.T) {
			mockManagementComponent.EXPECT().LockUser(ctx, realm, userID).Return(anyError)
			var _, err = e(ctx, req)
			assert.Equal(t, anyError, err)
		})
	})

	t.Run("UnlockUser", func(t *testing.T) {
		var e = MakeUnlockUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().UnlockUser(ctx, realm, userID).Return(nil)
			var res, err = e(ctx, req)
			assert.Nil(t, err)
			assert.Nil(t, res)
		})
		t.Run("Error occured", func(t *testing.T) {
			mockManagementComponent.EXPECT().UnlockUser(ctx, realm, userID).Return(anyError)
			var _, err = e(ctx, req)
			assert.Equal(t, anyError, err)
		})
	})
}

func TestGetUsersEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUsersEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		var realm = "master"
		var groupID1 = "123-784dsf-sdf567"
		var groupID2 = "789-741-753"
		var groupIDs = groupID1 + "," + groupID2
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmQryGroupIDs] = groupIDs

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{groupID1, groupID2}).Return(api.UsersPageRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmQryEmail] = "email@elca.ch"
		req[prmQryFirstName] = "firstname"
		req[prmQryLastName] = "lastname"
		req[prmQrySearch] = "search"
		req[prmQryUserName] = "username"
		req["toto"] = "tutu" // Check this param is not transmitted
		req[prmQryGroupIDs] = "123-784dsf-sdf567"

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{req[prmQryGroupIDs]}, "email", req[prmQryEmail], "firstName", req[prmQryFirstName], "lastName", req[prmQryLastName], "username", req[prmQryUserName], "search", req[prmQrySearch]).Return(api.UsersPageRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("Missing mandatory parameter group", func(t *testing.T) {
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestMakeGetUserChecksEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserChecksEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = map[string]string{prmRealm: realm, prmUserID: userID}
		var m = []api.UserCheck{}

		mockManagementComponent.EXPECT().GetUserChecks(ctx, realm, userID).Return(m, nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestGetUserAccountStatusEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserAccountStatusEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		var m = map[string]bool{"enabled": false}

		mockManagementComponent.EXPECT().GetUserAccountStatus(ctx, realm, userID).Return(m, nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestMakeGetUserAccountStatusByEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserAccountStatusByEmailEndpoint(mockManagementComponent)
	var ctx = context.Background()
	var realm = "one-realm"
	var email = "email@domain.ch"

	t.Run("MakeGetUserAccountStatusByEmailEndpoint-Missing user email", func(t *testing.T) {
		var req = map[string]string{"realm": realm}
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("MakeGetUserAccountStatusByEmailEndpoint-success", func(t *testing.T) {
		var req = map[string]string{prmRealm: realm, prmQryEmail: email}
		mockManagementComponent.EXPECT().GetUserAccountStatusByEmail(ctx, realm, email).Return(api.UserStatus{}, nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestUserRoleEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realm = "master"
	var userID = "123-123-456"
	var roleID = "rrr-ooo-lll-eee"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("MakeGetRolesOfUserEndpoint", func(t *testing.T) {
		var e = MakeGetRolesOfUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().GetRolesOfUser(ctx, realm, userID).Return([]api.RoleRepresentation{}, nil)
			var res, err = e(ctx, req)
			assert.Nil(t, err)
			assert.NotNil(t, res)
		})
	})

	req[prmRoleID] = roleID

	t.Run("MakeAddRoleToUserEndpoint", func(t *testing.T) {
		var e = MakeAddRoleToUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().AddRoleToUser(ctx, realm, userID, roleID).Return(nil)
			var resp, err = e(ctx, req)
			assert.Nil(t, err)
			assert.Equal(t, commonhttp.StatusNoContent{}, resp)
		})
	})
	t.Run("MakeDeleteRoleForUserEndpoint", func(t *testing.T) {
		var e = MakeDeleteRoleForUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().DeleteRoleForUser(ctx, realm, userID, roleID).Return(nil)
			var resp, err = e(ctx, req)
			assert.Nil(t, err)
			assert.Equal(t, commonhttp.StatusNoContent{}, resp)
		})
	})
}

func TestGetGroupsOfUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetGroupsOfUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().GetGroupsOfUser(ctx, realm, userID).Return([]api.GroupRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestSetGroupsToUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realm = "master"
	var userID = "123-123-456"
	var groupID = "grp1"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmGroupID] = groupID

	t.Run("AddGroup: No error", func(t *testing.T) {
		var e = MakeAddGroupToUserEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().AddGroupToUser(ctx, realm, userID, groupID).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("DeleteGroup: No error", func(t *testing.T) {
		var e = MakeDeleteGroupForUserEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().DeleteGroupForUser(ctx, realm, userID, groupID).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetAvailableTrustIDGroupsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetAvailableTrustIDGroupsEndpoint(mockManagementComponent)
	var realm = "master"
	var ctx = context.Background()
	var req = map[string]string{prmRealm: realm}

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realm).Return([]string{"grp1", "grp2"}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("Bad input", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realm).Return(nil, errors.New("error"))
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetTrustIDGroupsOfUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetTrustIDGroupsOfUserEndpoint(mockManagementComponent)
	var realm = "master"
	var userID = "123-123-456"
	var ctx = context.Background()
	var req = map[string]string{prmRealm: realm, prmUserID: userID}

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realm, userID).Return([]string{"grp1", "grp2"}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("Bad input", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realm, userID).Return(nil, errors.New("error"))
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestSetTrustIDGroupsToUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSetTrustIDGroupsToUserEndpoint(mockManagementComponent)

	t.Run("No error", func(t *testing.T) {
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		body := []string{"grp1", "grp2"}
		req[reqBody] = string("[\"grp1\", \"grp2\"]")

		mockManagementComponent.EXPECT().SetTrustIDGroupsToUser(ctx, realm, userID, body).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Bad input", func(t *testing.T) {
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[reqBody] = ""

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetClientRolesForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientRolesForUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var clientID = "456-789-741"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[prmClientID] = clientID

		mockManagementComponent.EXPECT().GetClientRolesForUser(ctx, realm, userID, clientID).Return([]api.RoleRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestAddClientRolesToUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeAddClientRolesToUserEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-123-456"
	var clientID = "456-789-741"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmClientID] = clientID

	t.Run("No error", func(t *testing.T) {
		roleJSON, _ := json.Marshal([]api.RoleRepresentation{})
		req[reqBody] = string(roleJSON)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realm, userID, clientID, []api.RoleRepresentation{}).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[reqBody] = string("roleJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestDeleteClientRolesFromUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteClientRolesFromUserEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-123-456"
	var clientID = "456-789-741"
	var roleID = "470cd9b2-d4a2-422a-97d0-7baa7c3ce494"
	var roleName = "testName"

	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmClientID] = clientID
	req[prmRoleID] = roleID
	req[prmQryRoleName] = roleName

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().DeleteClientRolesFromUser(ctx, realm, userID, clientID, roleID, roleName).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestResetPasswordEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeResetPasswordEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-123-456"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error", func(t *testing.T) {
		passwordJSON, _ := json.Marshal(api.PasswordRepresentation{})
		req[reqBody] = string(passwordJSON)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realm, userID, api.PasswordRepresentation{}).Return("", nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[reqBody] = string("passwordJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestExecuteActionsEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeExecuteActionsEmailEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var actions = []api.RequiredAction{"action1", "action2"}
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error - Without param", func(t *testing.T) {
		actionsJSON, _ := json.Marshal(actions)
		req[reqBody] = string(actionsJSON)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realm, userID, actions).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req["toto"] = "tutu" // Check this param is not transmitted
		actionsJSON, _ := json.Marshal(actions)
		req[reqBody] = string(actionsJSON)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realm, userID, actions, prmQryClientID, req[prmQryClientID], prmQryRedirectURI, req[prmQryRedirectURI]).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req[reqBody] = string("actions")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestMakeRevokeAccreditationsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeRevokeAccreditationsEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().RevokeAccreditations(ctx, realm, userID).Return(errors.New("any error"))
	var _, err = e(ctx, req)
	assert.NotNil(t, err)
}

func TestSendSmsCodeEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSendSmsCodeEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().SendSmsCode(ctx, realm, userID).Return("1234", nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, map[string]string{"code": "1234"}, res)

}

func TestSendOnboardingEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var lifespan = int(100 * time.Hour)
	var e = MakeSendOnboardingEmailEndpoint(mockManagementComponent, lifespan)

	var realm = "master"
	var customerRealm = "customer"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("Without reminder or customerRealm parameter", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, false, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is false", func(t *testing.T) {
		req[prmQryReminder] = "FALse"
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, false, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is true", func(t *testing.T) {
		req[prmQryReminder] = "TruE"
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, true, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is valid, lifespan not used", func(t *testing.T) {
		req[prmQryReminder] = "false"
		req[prmQryRealm] = customerRealm
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = "not-a-number"
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Too high lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = strconv.Itoa(int(500 * time.Hour))
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Valid lifespan submitted", func(t *testing.T) {
		var lifespan = strconv.Itoa(int(3 * 24 * time.Hour / time.Second))
		req[prmQryLifespan] = lifespan
		var expectedParamKV = []string{prmQryLifespan, lifespan}
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, expectedParamKV).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Valid custom parameters", func(t *testing.T) {
		delete(req, prmQryLifespan)
		req[prmQryCustom1] = "value1"
		req[prmQryCustom4] = "value4"
		var expectedParamKV = []string{prmQryCustom1, "value1", prmQryCustom4, "value4"}
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, expectedParamKV).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestSendOnboardingEmailInSocialRealmEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var lifespan = int(100 * time.Hour)
	var e = MakeSendOnboardingEmailInSocialRealmEndpoint(mockManagementComponent, lifespan)

	var realm = "master"
	var customerRealm = "customer"
	var ctxRealm = "context-realm"
	var userID = "123-456-789"
	var ctx = context.Background()
	ctx = context.WithValue(ctx, cs.CtContextRealm, ctxRealm)
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("Without reminder or customerRealm parameter", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, ctxRealm, false, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is false", func(t *testing.T) {
		req[prmQryReminder] = "FALse"
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, ctxRealm, false, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is true", func(t *testing.T) {
		req[prmQryReminder] = "TruE"
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, ctxRealm, true, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is valid, lifespan not used", func(t *testing.T) {
		req[prmQryReminder] = "false"
		req[prmQryRealm] = customerRealm
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, false, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = "not-a-number"
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Too high lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = strconv.Itoa(int(500 * time.Hour))
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Valid lifespan submitted", func(t *testing.T) {
		var lifespan = strconv.Itoa(int(3 * 24 * time.Hour / time.Second))
		req[prmQryLifespan] = lifespan
		var expectedParamKV = []string{prmQryLifespan, lifespan}
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, false, expectedParamKV).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestSendReminderEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSendReminderEmailEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error - Without param", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req[prmQryLifespan] = strconv.Itoa(3600)
		req["toto"] = "tutu" // Check this param is not transmitted

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID, prmQryClientID, req[prmQryClientID], prmQryRedirectURI, req[prmQryRedirectURI], prmQryLifespan, req[prmQryLifespan]).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
		// the mock does not except to be called with req["toto"]; as the test passes it means that e has filtered out req["tutu"] and it is not transmitted to SendReminderEmail
	})
}

func TestResetSmsCounterEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeResetSmsCounterEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().ResetSmsCounter(ctx, realm, userID).Return(nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)

}

func TestCodeEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	var responseCode = "123456"

	t.Run("RecoveryCode", func(t *testing.T) {
		var e = MakeCreateRecoveryCodeEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().CreateRecoveryCode(ctx, realm, userID).Return(responseCode, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, responseCode, res)
	})

	t.Run("ActivationCode", func(t *testing.T) {
		var e = MakeCreateActivationCodeEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().CreateActivationCode(ctx, realm, userID).Return(responseCode, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, responseCode, res)
	})
}

func TestGetCredentialsForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetCredentialsForUserEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().GetCredentialsForUser(ctx, realm, userID).Return([]api.CredentialRepresentation{}, nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	}
}

func TestDeleteCredentialsForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteCredentialsForUserEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var credID = "987-654-321"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[prmCredentialID] = credID

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realm, userID, credID).Return(nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	}
}

func TestResetCredentialFailuresForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeResetCredentialFailuresForUserEndpoint(mockManagementComponent)
	var ctx = context.Background()
	var req = make(map[string]string)

	t.Run("Valid query", func(t *testing.T) {
		var realm = "the-realm"
		var user = "the-user"
		var credential = "the-credential"
		mockManagementComponent.EXPECT().ResetCredentialFailuresForUser(ctx, realm, user, credential).Return(nil)
		req[prmRealm] = realm
		req[prmUserID] = user
		req[prmCredentialID] = credential
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestBruteForceEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	t.Run("MakeClearUserLoginFailures. No error. Without param", func(t *testing.T) {
		var e = MakeClearUserLoginFailures(mockManagementComponent)
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().ClearUserLoginFailures(ctx, realm, userID).Return(nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("MakeGetAttackDetectionStatus. No error. Without param", func(t *testing.T) {
		var e = MakeGetAttackDetectionStatus(mockManagementComponent)
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().GetAttackDetectionStatus(ctx, realm, userID).Return(api.AttackDetectionStatusRepresentation{}, nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestGetRolesEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRolesEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm

		mockManagementComponent.EXPECT().GetRoles(ctx, realm).Return([]api.RoleRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRoleEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var roleID = "123456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmRoleID] = roleID

		mockManagementComponent.EXPECT().GetRole(ctx, realm, roleID).Return(api.RoleRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestCreateRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateRoleEndpoint(mockManagementComponent, log.NewNopLogger())

	var realm = "master"
	var location = "https://location.url/auth/admin/master/roles/123456"
	var ctx = context.Background()

	var name = "name"

	t.Run("No error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm

		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req[reqBody] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateRole(ctx, realm, api.RoleRepresentation{Name: &name}).Return(location, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/roles/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req[reqBody] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateRole(ctx, realm, gomock.Any()).Return("", fmt.Errorf("Error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestMakeUpdateRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeUpdateRoleEndpoint(mockManagementComponent)

	var realm = "master"
	var roleID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmRoleID] = roleID

	t.Run("Missing body", func(t *testing.T) {
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
	})
	t.Run("Invalid body", func(t *testing.T) {
		req[reqBody] = `{"id":"123"}`
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
	})
	t.Run("Success", func(t *testing.T) {
		req[reqBody] = `{}`
		mockManagementComponent.EXPECT().UpdateRole(ctx, realm, roleID, gomock.Any()).Return(nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestDeleteRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteRoleEndpoint(mockManagementComponent)

	var realm = "master"
	var roleID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmRoleID] = roleID

	mockManagementComponent.EXPECT().DeleteRole(ctx, realm, roleID).Return(nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, commonhttp.StatusNoContent{}, res)
}

func TestGetGroupsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetGroupsEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm

		mockManagementComponent.EXPECT().GetGroups(ctx, realm).Return([]api.GroupRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestCreateGroupEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateGroupEndpoint(mockManagementComponent, log.NewNopLogger())

	var realm = "master"
	var location = "https://location.url/auth/admin/master/groups/123456"
	var ctx = context.Background()

	var name = "name"

	t.Run("No error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm

		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req[reqBody] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realm, api.GroupRepresentation{Name: &name}).Return(location, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/groups/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req[reqBody] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realm, gomock.Any()).Return("", fmt.Errorf("Error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestDeleteGroupEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteGroupEndpoint(mockManagementComponent)

	var realm = "master"
	var groupID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmGroupID] = groupID

	mockManagementComponent.EXPECT().DeleteGroup(ctx, realm, groupID).Return(nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)
}

func TestGetAuthorizationsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetAuthorizationsEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var groupID = "123456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmGroupID] = groupID

		mockManagementComponent.EXPECT().GetAuthorizations(ctx, realm, groupID).Return(api.AuthorizationsRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetClientRolesEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientRolesEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var clientID = "123456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmClientID] = clientID

		mockManagementComponent.EXPECT().GetClientRoles(ctx, realm, clientID).Return([]api.RoleRepresentation{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestUpdateAuthorizationsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeUpdateAuthorizationsEndpoint(mockManagementComponent)

	var realmName = "master"
	var groupID = "123456"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID

	t.Run("No error", func(t *testing.T) {
		req[reqBody] = `{"matrix":{}}`

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("JSON error", func(t *testing.T) {
		req[reqBody] = `{"DefaultClientId":"clientId", "DefaultRedirectUri":"http://cloudtrust.io"`

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestAddAuthorizationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeAddAuthorizationEndpoint(mockManagementComponent)

	var realmName = "master"
	var groupID = "123456"

	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID

	t.Run("No error", func(t *testing.T) {
		req[reqBody] = `{"matrix":{}}`
		mockManagementComponent.EXPECT().AddAuthorization(ctx, realmName, groupID, gomock.Any()).Return(nil)

		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("JSON error", func(t *testing.T) {
		req[reqBody] = `{"matrix":{}`
		mockManagementComponent.EXPECT().AddAuthorization(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(0)

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetAuthorizationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetAuthorizationEndpoint(mockManagementComponent)

	var realmName = "master"
	var groupID = "123456"
	var targetRealmName = "master"
	var targetGroupID = "456789"
	var action = "TestAction"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID
	req[prmQryTargetRealm] = targetRealmName
	req[prmQryTargetGroupID] = targetGroupID
	req[prmAction] = action

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action).Return(api.AuthorizationMessage{}, nil)

		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, api.AuthorizationMessage{}, res)
	})
}

func TestDeleteAuthorizationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteAuthorizationEndpoint(mockManagementComponent)

	var realmName = "master"
	var groupID = "123456"
	var targetRealmName = "master"
	var targetGroupID = "456789"
	var action = "TestAction"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID
	req[prmQryTargetRealm] = targetRealmName
	req[prmQryTargetGroupID] = targetGroupID
	req[prmAction] = action

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action).Return(nil)

		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestCreateClientRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateClientRoleEndpoint(mockManagementComponent, log.NewNopLogger())
	var ctx = context.Background()
	var location = "https://location.url/auth/admin/master/role/123456"
	var realm = "master"
	var clientID = "123456"

	t.Run("No error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		req[prmClientID] = clientID
		roleJSON, _ := json.Marshal(api.RoleRepresentation{})
		req[reqBody] = string(roleJSON)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realm, clientID, api.RoleRepresentation{}).Return(location, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/role/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		req[prmClientID] = clientID
		userJSON, _ := json.Marshal(api.RoleRepresentation{})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realm, clientID, gomock.Any()).Return("", fmt.Errorf("Error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestDeleteClientRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteClientRoleEndpoint(mockManagementComponent)

	var realm = "test"
	var clientID = "65461-4568"
	var roleID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmClientID] = clientID
	req[prmRoleID] = roleID

	mockManagementComponent.EXPECT().DeleteClientRole(ctx, realm, clientID, roleID).Return(nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, commonhttp.StatusNoContent{}, res)
}

func TestMakeGetRealmUserProfileEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)
	var e = MakeGetRealmUserProfileEndpoint(mockManagementComponent)

	var realmName = "the-realm"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realmName

	mockManagementComponent.EXPECT().GetRealmUserProfile(ctx, realmName).Return(apicommon.ProfileRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestConfigurationEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realmName = "master"
	var clientID = "123456"
	var groupName = "my-group"
	var ctx = context.Background()

	t.Run("MakeGetRealmCustomConfigurationEndpoint - No error", func(t *testing.T) {
		var req = map[string]string{prmRealm: realmName, prmClientID: clientID}
		var e = MakeGetRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().GetRealmCustomConfiguration(ctx, realmName).Return(api.RealmCustomConfiguration{}, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - No error", func(t *testing.T) {
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\"}"
		var req = map[string]string{prmRealm: realmName, prmClientID: clientID, reqBody: configJSON}
		var e = MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - JSON error", func(t *testing.T) {
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\""
		var req = map[string]string{prmRealm: realmName, prmClientID: clientID, reqBody: configJSON}
		var e = MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeGetRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var expectedConf api.BackOfficeConfiguration
		var expectedErr = errors.New("any error")
		var e = MakeGetRealmBackOfficeConfigurationEndpoint(mockManagementComponent)
		var req = map[string]string{prmRealm: realmName, prmQryGroupName: groupName}

		t.Run("Bad request", func(t *testing.T) {
			req[prmQryGroupName] = ""
			var _, err = e(ctx, req)
			assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
		})
		t.Run("Success", func(t *testing.T) {
			req[prmQryGroupName] = groupName
			mockManagementComponent.EXPECT().GetRealmBackOfficeConfiguration(ctx, realmName, groupName).Return(expectedConf, expectedErr)
			var res, err = e(ctx, req)
			assert.Equal(t, expectedErr, err)
			assert.Equal(t, expectedConf, res)
		})
	})

	t.Run("MakeUpdateRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var config api.BackOfficeConfiguration
		var configJSON, _ = json.Marshal(config)
		var req = map[string]string{prmRealm: realmName, prmQryGroupName: groupName}
		var expectedErr = errors.New("update error")
		var e = MakeUpdateRealmBackOfficeConfigurationEndpoint(mockManagementComponent)

		t.Run("Body is not a JSON value", func(t *testing.T) {
			req[reqBody] = `{]`
			var _, err = e(ctx, req)
			assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
		})
		t.Run("Missing groupName", func(t *testing.T) {
			req[reqBody] = string(configJSON)
			req[prmQryGroupName] = ""
			var _, err = e(ctx, req)
			assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
		})
		t.Run("Success", func(t *testing.T) {
			req[prmQryGroupName] = groupName
			mockManagementComponent.EXPECT().UpdateRealmBackOfficeConfiguration(ctx, realmName, groupName, config).Return(expectedErr)
			var res, err = e(ctx, req)
			assert.Equal(t, expectedErr, err)
			assert.Nil(t, res)
		})
	})

	t.Run("MakeGetUserRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var e = MakeGetUserRealmBackOfficeConfigurationEndpoint(mockManagementComponent)
		var expectedResult = api.BackOfficeConfiguration{}
		var req = map[string]string{prmRealm: realmName}
		var ctx = context.TODO()
		mockManagementComponent.EXPECT().GetUserRealmBackOfficeConfiguration(ctx, realmName).Return(expectedResult, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, expectedResult, res)
	})
}

func TestGetRealmAdminConfigurationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmAdminConfigurationEndpoint(mockManagementComponent)
	var ctx = context.Background()

	t.Run("No error", func(t *testing.T) {
		var realmName = "master"
		var adminConfig api.RealmAdminConfiguration
		var req = make(map[string]string)
		req[prmRealm] = realmName

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})
	t.Run("Request fails at component level", func(t *testing.T) {
		var realmName = "master"
		var adminConfig api.RealmAdminConfiguration
		var expectedError = errors.New("component error")
		var req = make(map[string]string)
		req[prmRealm] = realmName

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, expectedError)
		var _, err = e(ctx, req)
		assert.Equal(t, expectedError, err)
	})
}

func TestUpdateRealmAdminConfigurationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeUpdateRealmAdminConfigurationEndpoint(mockManagementComponent)
	var ctx = context.Background()

	t.Run("No error", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{"mode":"trustID"}`
		var req = make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, gomock.Any()).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid body content", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{}`
		var req = make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("JSON error", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{`
		var req = make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetFederatedIdentitiesEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetFederatedIdentitiesEndpoint(mockManagementComponent)

	var realm = "realm-name"
	var userID = "user-id"
	var ctx = context.Background()

	var req = map[string]string{
		prmRealm:  realm,
		prmUserID: userID,
	}

	mockManagementComponent.EXPECT().GetFederatedIdentities(ctx, realm, userID).Return([]api.FederatedIdentityRepresentation{}, nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestLinkShadowUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeLinkShadowUserEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var username = "username"
	var userID = "abcdefgh-1234-ijkl-5678-mnopqrstuvwx"
	var provider = "provider"

	var req = make(map[string]string)
	req[prmUserID] = userID
	req[prmProvider] = provider
	req[prmRealm] = realm

	fedID, _ := json.Marshal(api.FederatedIdentityRepresentation{Username: &username, UserID: &userID})
	req[reqBody] = string(fedID)

	// No error
	t.Run("Create shadow user successfully", func(t *testing.T) {
		mockManagementComponent.EXPECT().LinkShadowUser(ctx, realm, userID, provider, api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}).Return(nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

	// Error
	t.Run("Create shadow user - error at unmarshal", func(t *testing.T) {
		var req2 = map[string]string{reqBody: "JSON"}
		_, err := e(ctx, req2)
		assert.NotNil(t, err)
	})

	// Error - Keycloak client error
	t.Run("Create shadow user - error at KC client", func(t *testing.T) {

		mockManagementComponent.EXPECT().LinkShadowUser(ctx, realm, userID, provider, api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}).Return(fmt.Errorf("error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestGetIdentityProvidersEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetIdentityProvidersEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetIdentityProviders(ctx, realm).Return([]api.IdentityProviderRepresentation{}, nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestConvertLocationUrl(t *testing.T) {

	res, err := convertLocationURL("http://localhost:8080/auth/realms/master/api/admin/realms/dep/users/1522-4245245-4542545/credentials", "https", "ct-bridge.services.com")
	assert.Equal(t, "https://ct-bridge.services.com/management/realms/dep/users/1522-4245245-4542545/credentials", res)
	assert.Nil(t, err)

	res, err = convertLocationURL("http://localhost:8080/auth/admin/realms/dep/users/1522-4245245-4542545", "https", "ct-bridge.services.com")
	assert.Equal(t, "https://ct-bridge.services.com/management/realms/dep/users/1522-4245245-4542545", res)
	assert.Nil(t, err)

	res, err = convertLocationURL("http://localhost:8080/toto", "https", "ct-bridge.services.com")
	assert.Equal(t, "InvalidLocation", res)
	assert.Equal(t, ConvertLocationError{Location: "http://localhost:8080/toto"}, err)

}
