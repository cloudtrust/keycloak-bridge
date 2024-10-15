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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetActionsEndpoint(mockManagementComponent)

	ctx := context.Background()

	mockManagementComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil)
	res, err := e(ctx, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetRealmsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetRealmsEndpoint(mockManagementComponent)

	ctx := context.Background()
	req := make(map[string]string)

	mockManagementComponent.EXPECT().GetRealms(ctx).Return([]api.RealmRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetRealmEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetRealmEndpoint(mockManagementComponent)

	realm := "master"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetRealm(ctx, realm).Return(api.RealmRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetClientEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetClientEndpoint(mockManagementComponent)

	realm := "master"
	clientID := "1234-4567-7895"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmClientID] = clientID

	mockManagementComponent.EXPECT().GetClient(ctx, realm, clientID).Return(api.ClientRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetClientsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetClientsEndpoint(mockManagementComponent)

	realm := "master"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetClients(ctx, realm).Return([]api.ClientRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetRequiredActionsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetRequiredActionsEndpoint(mockManagementComponent)

	realm := "master"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetRequiredActions(ctx, realm).Return([]api.RequiredActionRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestCreateUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockProfileCache        = mock.NewUserProfileCache(mockCtrl)
		mockManagementComponent = mock.NewManagementComponent(mockCtrl)

		e = MakeCreateUserEndpoint(mockManagementComponent, mockProfileCache, log.NewNopLogger())

		realm    = "master"
		location = "https://location.url/auth/admin/master/users/123456"
		ctx      = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		groups   = []string{"f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"}
		anyError = errors.New("any")
	)

	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		req := map[string]string{reqBody: "{}"}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(kc.UserProfileRepresentation{
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
		user := api.UserRepresentation{Gender: ptr("M"), Groups: &groups}
		userJSON, _ := json.Marshal(user)
		req := map[string]string{
			reqScheme: "https",
			reqHost:   "elca.ch",
			prmRealm:  realm,
			reqBody:   string(userJSON),
		}

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, user, false, false, false).Return(location, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/users/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Invalid body", func(t *testing.T) {
		req := map[string]string{reqBody: `{}`}
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Missing groups", func(t *testing.T) {
		req := make(map[string]string)
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: nil})
		req[reqBody] = string(userJSON)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, gomock.Any(), false, false, false).Return("", fmt.Errorf("Error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Unparsable location", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, api.UserRepresentation{Groups: &groups}, false, false, false).Return("/unrecognized/location", nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.IsType(t, LocationHeader{}, res)
		hdr := res.(LocationHeader)
		assert.Equal(t, invalidLocation, hdr.URL)
	})
}

func TestCreateUserInSocialRealmEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockProfileCache        = mock.NewUserProfileCache(mockCtrl)
		mockManagementComponent = mock.NewManagementComponent(mockCtrl)

		e = MakeCreateUserInSocialRealmEndpoint(mockManagementComponent, mockProfileCache, log.NewNopLogger())

		realm    = "master"
		location = "https://location.url/auth/admin/master/users/123456"
		ctx      = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		groups   = []string{"f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"}
		anyError = errors.New("any")
	)

	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		req := map[string]string{reqBody: "{}"}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(kc.UserProfileRepresentation{
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
		req := map[string]string{
			reqScheme: "https",
			reqHost:   "elca.ch",
			prmRealm:  realm,
		}
		user := api.UserRepresentation{Gender: ptr("M"), Groups: &groups}

		userJSON, _ := json.Marshal(user)
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUserInSocialRealm(ctx, user, false).Return(location, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/users/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		req := map[string]string{reqBody: "JSON"}
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Invalid body", func(t *testing.T) {
		req := map[string]string{reqBody: `{"email":""}`}
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Missing groups", func(t *testing.T) {
		req := make(map[string]string)
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: nil})
		req[reqBody] = string(userJSON)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUserInSocialRealm(ctx, gomock.Any(), false).Return("", fmt.Errorf("Error"))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Unparsable location", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUserInSocialRealm(ctx, api.UserRepresentation{Groups: &groups}, false).Return("/unrecognized/location", nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.IsType(t, LocationHeader{}, res)
		hdr := res.(LocationHeader)
		assert.Equal(t, invalidLocation, hdr.URL)
	})
}

func TestDeleteUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeDeleteUserEndpoint(mockManagementComponent)

	realm := "master"
	userID := "1234-452-4578"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().DeleteUser(ctx, realm, userID).Return(nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)
}

func TestGetUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetUserEndpoint(mockManagementComponent)

	realm := "master"
	userID := "1234-452-4578"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().GetUser(ctx, realm, userID).Return(api.UserRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestUpdateUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockProfileCache        = mock.NewUserProfileCache(mockCtrl)
		mockManagementComponent = mock.NewManagementComponent(mockCtrl)

		e = MakeUpdateUserEndpoint(mockManagementComponent, mockProfileCache, log.NewNopLogger())

		realm    = "the-realm"
		userID   = "1234-452-4578"
		theUser  = api.UserRepresentation{Gender: ptr("M")}
		ctx      = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		anyError = errors.New("any")
	)

	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		req := map[string]string{reqBody: "{}"}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(kc.UserProfileRepresentation{
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
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		userJSON, _ := json.Marshal(theUser)
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[reqBody] = string("userJSON")

		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestLockUserEndpoints(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	realm := "master"
	userID := "1234-452-4578"
	anyError := errors.New("any")
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("LockUser", func(t *testing.T) {
		e := MakeLockUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().LockUser(ctx, realm, userID).Return(nil)
			res, err := e(ctx, req)
			assert.Nil(t, err)
			assert.Nil(t, res)
		})
		t.Run("Error occured", func(t *testing.T) {
			mockManagementComponent.EXPECT().LockUser(ctx, realm, userID).Return(anyError)
			_, err := e(ctx, req)
			assert.Equal(t, anyError, err)
		})
	})

	t.Run("UnlockUser", func(t *testing.T) {
		e := MakeUnlockUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().UnlockUser(ctx, realm, userID).Return(nil)
			res, err := e(ctx, req)
			assert.Nil(t, err)
			assert.Nil(t, res)
		})
		t.Run("Error occured", func(t *testing.T) {
			mockManagementComponent.EXPECT().UnlockUser(ctx, realm, userID).Return(anyError)
			_, err := e(ctx, req)
			assert.Equal(t, anyError, err)
		})
	})
}

func TestGetUsersEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetUsersEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		realm := "master"
		groupID1 := "123-784dsf-sdf567"
		groupID2 := "789-741-753"
		groupIDs := groupID1 + "," + groupID2
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmQryGroupIDs] = groupIDs

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{groupID1, groupID2}).Return(api.UsersPageRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		realm := "master"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmQryEmail] = "email@elca.ch"
		req[prmQryFirstName] = "firstname"
		req[prmQryLastName] = "lastname"
		req[prmQrySearch] = "search"
		req[prmQryUserName] = "username"
		req["toto"] = "tutu" // Check this param is not transmitted
		req[prmQryGroupIDs] = "123-784dsf-sdf567"

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{req[prmQryGroupIDs]}, "email", req[prmQryEmail], "firstName", req[prmQryFirstName], "lastName", req[prmQryLastName], "username", req[prmQryUserName], "search", req[prmQrySearch]).Return(api.UsersPageRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("Missing mandatory parameter group", func(t *testing.T) {
		realm := "master"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm

		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestMakeGetUserChecksEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetUserChecksEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		realm := "master"
		userID := "123-456-789"
		ctx := context.Background()
		req := map[string]string{prmRealm: realm, prmUserID: userID}
		m := []api.UserCheck{}

		mockManagementComponent.EXPECT().GetUserChecks(ctx, realm, userID).Return(m, nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestGetUserAccountStatusEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetUserAccountStatusEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		realm := "master"
		userID := "123-456-789"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		m := map[string]bool{"enabled": false}

		mockManagementComponent.EXPECT().GetUserAccountStatus(ctx, realm, userID).Return(m, nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestMakeGetUserAccountStatusByEmailEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetUserAccountStatusByEmailEndpoint(mockManagementComponent)
	ctx := context.Background()
	realm := "one-realm"
	email := "email@domain.ch"

	t.Run("MakeGetUserAccountStatusByEmailEndpoint-Missing user email", func(t *testing.T) {
		req := map[string]string{"realm": realm}
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("MakeGetUserAccountStatusByEmailEndpoint-success", func(t *testing.T) {
		req := map[string]string{prmRealm: realm, prmQryEmail: email}
		mockManagementComponent.EXPECT().GetUserAccountStatusByEmail(ctx, realm, email).Return(api.UserStatus{}, nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestUserRoleEndpoints(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	realm := "master"
	userID := "123-123-456"
	roleID := "rrr-ooo-lll-eee"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("MakeGetRolesOfUserEndpoint", func(t *testing.T) {
		e := MakeGetRolesOfUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().GetRolesOfUser(ctx, realm, userID).Return([]api.RoleRepresentation{}, nil)
			res, err := e(ctx, req)
			assert.Nil(t, err)
			assert.NotNil(t, res)
		})
	})

	req[prmRoleID] = roleID

	t.Run("MakeAddRoleToUserEndpoint", func(t *testing.T) {
		e := MakeAddRoleToUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().AddRoleToUser(ctx, realm, userID, roleID).Return(nil)
			resp, err := e(ctx, req)
			assert.Nil(t, err)
			assert.Equal(t, commonhttp.StatusNoContent{}, resp)
		})
	})
	t.Run("MakeDeleteRoleForUserEndpoint", func(t *testing.T) {
		e := MakeDeleteRoleForUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().DeleteRoleForUser(ctx, realm, userID, roleID).Return(nil)
			resp, err := e(ctx, req)
			assert.Nil(t, err)
			assert.Equal(t, commonhttp.StatusNoContent{}, resp)
		})
	})
}

func TestGetGroupsOfUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetGroupsOfUserEndpoint(mockManagementComponent)

	// No error
	{
		realm := "master"
		userID := "123-123-456"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().GetGroupsOfUser(ctx, realm, userID).Return([]api.GroupRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestSetGroupsToUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	realm := "master"
	userID := "123-123-456"
	groupID := "grp1"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmGroupID] = groupID

	t.Run("AddGroup: No error", func(t *testing.T) {
		e := MakeAddGroupToUserEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().AddGroupToUser(ctx, realm, userID, groupID).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("DeleteGroup: No error", func(t *testing.T) {
		e := MakeDeleteGroupForUserEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().DeleteGroupForUser(ctx, realm, userID, groupID).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetAvailableTrustIDGroupsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetAvailableTrustIDGroupsEndpoint(mockManagementComponent)
	realm := "master"
	ctx := context.Background()
	req := map[string]string{prmRealm: realm}

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realm).Return([]string{"grp1", "grp2"}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("Bad input", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realm).Return(nil, errors.New("error"))
		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetTrustIDGroupsOfUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetTrustIDGroupsOfUserEndpoint(mockManagementComponent)
	realm := "master"
	userID := "123-123-456"
	ctx := context.Background()
	req := map[string]string{prmRealm: realm, prmUserID: userID}

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realm, userID).Return([]string{"grp1", "grp2"}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("Bad input", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realm, userID).Return(nil, errors.New("error"))
		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestSetTrustIDGroupsToUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeSetTrustIDGroupsToUserEndpoint(mockManagementComponent)

	t.Run("No error", func(t *testing.T) {
		realm := "master"
		userID := "123-123-456"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		body := []string{"grp1", "grp2"}
		req[reqBody] = string("[\"grp1\", \"grp2\"]")

		mockManagementComponent.EXPECT().SetTrustIDGroupsToUser(ctx, realm, userID, body).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Bad input", func(t *testing.T) {
		realm := "master"
		userID := "123-123-456"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[reqBody] = ""

		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetClientRolesForUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetClientRolesForUserEndpoint(mockManagementComponent)

	// No error
	{
		realm := "master"
		userID := "123-123-456"
		clientID := "456-789-741"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[prmClientID] = clientID

		mockManagementComponent.EXPECT().GetClientRolesForUser(ctx, realm, userID, clientID).Return([]api.RoleRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestAddClientRolesToUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeAddClientRolesToUserEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-123-456"
	clientID := "456-789-741"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmClientID] = clientID

	t.Run("No error", func(t *testing.T) {
		roleJSON, _ := json.Marshal([]api.RoleRepresentation{})
		req[reqBody] = string(roleJSON)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realm, userID, clientID, []api.RoleRepresentation{}).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[reqBody] = string("roleJSON")

		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestDeleteClientRolesFromUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeDeleteClientRolesFromUserEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-123-456"
	clientID := "456-789-741"
	roleID := "470cd9b2-d4a2-422a-97d0-7baa7c3ce494"
	roleName := "testName"

	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmClientID] = clientID
	req[prmRoleID] = roleID
	req[prmQryRoleName] = roleName

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().DeleteClientRolesFromUser(ctx, realm, userID, clientID, roleID, roleName).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestResetPasswordEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeResetPasswordEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-123-456"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error", func(t *testing.T) {
		passwordJSON, _ := json.Marshal(api.PasswordRepresentation{})
		req[reqBody] = string(passwordJSON)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realm, userID, api.PasswordRepresentation{}).Return("", nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[reqBody] = string("passwordJSON")

		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestExecuteActionsEmailEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeExecuteActionsEmailEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-456-789"
	actions := []api.RequiredAction{"action1", "action2"}
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error - Without param", func(t *testing.T) {
		actionsJSON, _ := json.Marshal(actions)
		req[reqBody] = string(actionsJSON)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realm, userID, actions).Return(nil)
		res, err := e(ctx, req)
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
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req[reqBody] = string("actions")

		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestMakeRevokeAccreditationsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeRevokeAccreditationsEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-456-789"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().RevokeAccreditations(ctx, realm, userID).Return(errors.New("any error"))
	_, err := e(ctx, req)
	assert.NotNil(t, err)
}

func TestSendSmsCodeEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeSendSmsCodeEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-456-789"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().SendSmsCode(ctx, realm, userID).Return("1234", nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, map[string]string{"code": "1234"}, res)
}

func TestSendOnboardingEmailEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	lifespan := int(100 * time.Hour)
	e := MakeSendOnboardingEmailEndpoint(mockManagementComponent, lifespan)

	realm := "master"
	customerRealm := "customer"
	userID := "123-456-789"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("Without reminder or customerRealm parameter", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, false, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is false", func(t *testing.T) {
		req[prmQryReminder] = "FALse"
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, false, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is true", func(t *testing.T) {
		req[prmQryReminder] = "TruE"
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, true, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is valid, lifespan not used", func(t *testing.T) {
		req[prmQryReminder] = "false"
		req[prmQryRealm] = customerRealm
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = "not-a-number"
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Too high lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = strconv.Itoa(int(500 * time.Hour))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Valid lifespan submitted", func(t *testing.T) {
		lifespan := strconv.Itoa(int(3 * 24 * time.Hour / time.Second))
		req[prmQryLifespan] = lifespan
		expectedParamKV := []string{prmQryLifespan, lifespan}
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, expectedParamKV).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Valid custom parameters", func(t *testing.T) {
		delete(req, prmQryLifespan)
		req[prmQryCustom1] = "value1"
		req[prmQryCustom4] = "value4"
		expectedParamKV := []string{prmQryCustom1, "value1", prmQryCustom4, "value4"}
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, expectedParamKV).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestSendOnboardingEmailInSocialRealmEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	lifespan := int(100 * time.Hour)
	e := MakeSendOnboardingEmailInSocialRealmEndpoint(mockManagementComponent, lifespan)

	realm := "master"
	customerRealm := "customer"
	ctxRealm := "context-realm"
	userID := "123-456-789"
	ctx := context.Background()
	ctx = context.WithValue(ctx, cs.CtContextRealm, ctxRealm)
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("Without reminder or customerRealm parameter", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, ctxRealm, false, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is false", func(t *testing.T) {
		req[prmQryReminder] = "FALse"
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, ctxRealm, false, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is true", func(t *testing.T) {
		req[prmQryReminder] = "TruE"
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, ctxRealm, true, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is valid, lifespan not used", func(t *testing.T) {
		req[prmQryReminder] = "false"
		req[prmQryRealm] = customerRealm
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, false, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = "not-a-number"
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Too high lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = strconv.Itoa(int(500 * time.Hour))
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Valid lifespan submitted", func(t *testing.T) {
		lifespan := strconv.Itoa(int(3 * 24 * time.Hour / time.Second))
		req[prmQryLifespan] = lifespan
		expectedParamKV := []string{prmQryLifespan, lifespan}
		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, false, expectedParamKV).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestSendReminderEmailEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeSendReminderEmailEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-456-789"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error - Without param", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req[prmQryLifespan] = strconv.Itoa(3600)
		req["toto"] = "tutu" // Check this param is not transmitted

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID, prmQryClientID, req[prmQryClientID], prmQryRedirectURI, req[prmQryRedirectURI], prmQryLifespan, req[prmQryLifespan]).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
		// the mock does not except to be called with req["toto"]; as the test passes it means that e has filtered out req["tutu"] and it is not transmitted to SendReminderEmail
	})
}

func TestResetSmsCounterEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeResetSmsCounterEndpoint(mockManagementComponent)

	realm := "master"
	userID := "123-456-789"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().ResetSmsCounter(ctx, realm, userID).Return(nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)
}

func TestCodeEndpoints(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	realm := "master"
	userID := "123-456-789"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	responseCode := "123456"

	t.Run("RecoveryCode", func(t *testing.T) {
		e := MakeCreateRecoveryCodeEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().CreateRecoveryCode(ctx, realm, userID).Return(responseCode, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, responseCode, res)
	})

	t.Run("ActivationCode", func(t *testing.T) {
		e := MakeCreateActivationCodeEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().CreateActivationCode(ctx, realm, userID).Return(responseCode, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, responseCode, res)
	})
}

func TestGetCredentialsForUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetCredentialsForUserEndpoint(mockManagementComponent)

	// No error - Without param
	{
		realm := "master"
		userID := "123-456-789"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().GetCredentialsForUser(ctx, realm, userID).Return([]api.CredentialRepresentation{}, nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	}
}

func TestDeleteCredentialsForUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeDeleteCredentialsForUserEndpoint(mockManagementComponent)

	// No error - Without param
	{
		realm := "master"
		userID := "123-456-789"
		credID := "987-654-321"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[prmCredentialID] = credID

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realm, userID, credID).Return(nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	}
}

func TestResetCredentialFailuresForUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeResetCredentialFailuresForUserEndpoint(mockManagementComponent)
	ctx := context.Background()
	req := make(map[string]string)

	t.Run("Valid query", func(t *testing.T) {
		realm := "the-realm"
		user := "the-user"
		credential := "the-credential"
		mockManagementComponent.EXPECT().ResetCredentialFailuresForUser(ctx, realm, user, credential).Return(nil)
		req[prmRealm] = realm
		req[prmUserID] = user
		req[prmCredentialID] = credential
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestBruteForceEndpoints(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	t.Run("MakeClearUserLoginFailures. No error. Without param", func(t *testing.T) {
		e := MakeClearUserLoginFailures(mockManagementComponent)
		realm := "master"
		userID := "123-456-789"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().ClearUserLoginFailures(ctx, realm, userID).Return(nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("MakeGetAttackDetectionStatus. No error. Without param", func(t *testing.T) {
		e := MakeGetAttackDetectionStatus(mockManagementComponent)
		realm := "master"
		userID := "123-456-789"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().GetAttackDetectionStatus(ctx, realm, userID).Return(api.AttackDetectionStatusRepresentation{}, nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestGetRolesEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetRolesEndpoint(mockManagementComponent)

	// No error
	{
		realm := "master"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm

		mockManagementComponent.EXPECT().GetRoles(ctx, realm).Return([]api.RoleRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetRoleEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetRoleEndpoint(mockManagementComponent)

	// No error
	{
		realm := "master"
		roleID := "123456"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmRoleID] = roleID

		mockManagementComponent.EXPECT().GetRole(ctx, realm, roleID).Return(api.RoleRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestCreateRoleEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeCreateRoleEndpoint(mockManagementComponent, log.NewNopLogger())

	realm := "master"
	location := "https://location.url/auth/admin/master/roles/123456"
	ctx := context.Background()

	name := "name"

	t.Run("No error", func(t *testing.T) {
		req := make(map[string]string)
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
		req := make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeUpdateRoleEndpoint(mockManagementComponent)

	realm := "master"
	roleID := "1234-452-4578"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmRoleID] = roleID

	t.Run("Missing body", func(t *testing.T) {
		_, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
	})
	t.Run("Invalid body", func(t *testing.T) {
		req[reqBody] = `{"id":"123"}`
		_, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
	})
	t.Run("Success", func(t *testing.T) {
		req[reqBody] = `{}`
		mockManagementComponent.EXPECT().UpdateRole(ctx, realm, roleID, gomock.Any()).Return(nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestDeleteRoleEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeDeleteRoleEndpoint(mockManagementComponent)

	realm := "master"
	roleID := "1234-452-4578"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmRoleID] = roleID

	mockManagementComponent.EXPECT().DeleteRole(ctx, realm, roleID).Return(nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, commonhttp.StatusNoContent{}, res)
}

func TestGetGroupsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetGroupsEndpoint(mockManagementComponent)

	// No error
	{
		realm := "master"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm

		mockManagementComponent.EXPECT().GetGroups(ctx, realm).Return([]api.GroupRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestCreateGroupEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeCreateGroupEndpoint(mockManagementComponent, log.NewNopLogger())

	realm := "master"
	location := "https://location.url/auth/admin/master/groups/123456"
	ctx := context.Background()

	name := "name"

	t.Run("No error", func(t *testing.T) {
		req := make(map[string]string)
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
		req := make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeDeleteGroupEndpoint(mockManagementComponent)

	realm := "master"
	groupID := "1234-452-4578"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmGroupID] = groupID

	mockManagementComponent.EXPECT().DeleteGroup(ctx, realm, groupID).Return(nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)
}

func TestGetAuthorizationsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetAuthorizationsEndpoint(mockManagementComponent)

	// No error
	{
		realm := "master"
		groupID := "123456"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmGroupID] = groupID

		mockManagementComponent.EXPECT().GetAuthorizations(ctx, realm, groupID).Return(api.AuthorizationsRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetClientRolesEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetClientRolesEndpoint(mockManagementComponent)

	// No error
	{
		realm := "master"
		clientID := "123456"
		ctx := context.Background()
		req := make(map[string]string)
		req[prmRealm] = realm
		req[prmClientID] = clientID

		mockManagementComponent.EXPECT().GetClientRoles(ctx, realm, clientID).Return([]api.RoleRepresentation{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestUpdateAuthorizationsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeUpdateAuthorizationsEndpoint(mockManagementComponent)

	realmName := "master"
	groupID := "123456"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID

	t.Run("No error", func(t *testing.T) {
		req[reqBody] = `{"matrix":{}}`

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("JSON error", func(t *testing.T) {
		req[reqBody] = `{"DefaultClientId":"clientId", "DefaultRedirectUri":"http://cloudtrust.io"`

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(0)
		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestAddAuthorizationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeAddAuthorizationEndpoint(mockManagementComponent)

	realmName := "master"
	groupID := "123456"

	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID

	t.Run("No error", func(t *testing.T) {
		req[reqBody] = `{"matrix":{}}`
		mockManagementComponent.EXPECT().AddAuthorization(ctx, realmName, groupID, gomock.Any()).Return(nil)

		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("JSON error", func(t *testing.T) {
		req[reqBody] = `{"matrix":{}`
		mockManagementComponent.EXPECT().AddAuthorization(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(0)

		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetAuthorizationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetAuthorizationEndpoint(mockManagementComponent)

	realmName := "master"
	groupID := "123456"
	targetRealmName := "master"
	targetGroupID := "456789"
	action := "TestAction"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID
	req[prmQryTargetRealm] = targetRealmName
	req[prmQryTargetGroupID] = targetGroupID
	req[prmAction] = action

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action).Return(api.AuthorizationMessage{}, nil)

		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, api.AuthorizationMessage{}, res)
	})
}

func TestDeleteAuthorizationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeDeleteAuthorizationEndpoint(mockManagementComponent)

	realmName := "master"
	groupID := "123456"
	targetRealmName := "master"
	targetGroupID := "456789"
	action := "TestAction"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID
	req[prmQryTargetRealm] = targetRealmName
	req[prmQryTargetGroupID] = targetGroupID
	req[prmAction] = action

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().DeleteAuthorization(ctx, realmName, groupID, targetRealmName, targetGroupID, action).Return(nil)

		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestCreateClientRoleEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeCreateClientRoleEndpoint(mockManagementComponent, log.NewNopLogger())
	ctx := context.Background()
	location := "https://location.url/auth/admin/master/role/123456"
	realm := "master"
	clientID := "123456"

	t.Run("No error", func(t *testing.T) {
		req := make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		req[prmClientID] = clientID
		roleJSON, _ := json.Marshal(api.RoleRepresentation{})
		req[reqBody] = string(roleJSON)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realm, clientID, api.RoleRepresentation{}).Return(location, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/role/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		req := make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		req := make(map[string]string)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeDeleteClientRoleEndpoint(mockManagementComponent)

	realm := "test"
	clientID := "65461-4568"
	roleID := "1234-452-4578"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realm
	req[prmClientID] = clientID
	req[prmRoleID] = roleID

	mockManagementComponent.EXPECT().DeleteClientRole(ctx, realm, clientID, roleID).Return(nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, commonhttp.StatusNoContent{}, res)
}

func TestMakeGetRealmUserProfileEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)
	e := MakeGetRealmUserProfileEndpoint(mockManagementComponent)

	realmName := "the-realm"
	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = realmName

	mockManagementComponent.EXPECT().GetRealmUserProfile(ctx, realmName).Return(apicommon.ProfileRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestConfigurationEndpoints(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	realmName := "master"
	clientID := "123456"
	groupName := "my-group"
	ctx := context.Background()

	t.Run("MakeGetRealmCustomConfigurationEndpoint - No error", func(t *testing.T) {
		req := map[string]string{prmRealm: realmName, prmClientID: clientID}
		e := MakeGetRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().GetRealmCustomConfiguration(ctx, realmName).Return(api.RealmCustomConfiguration{}, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - No error", func(t *testing.T) {
		configJSON := "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\"}"
		req := map[string]string{prmRealm: realmName, prmClientID: clientID, reqBody: configJSON}
		e := MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - JSON error", func(t *testing.T) {
		configJSON := "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\""
		req := map[string]string{prmRealm: realmName, prmClientID: clientID, reqBody: configJSON}
		e := MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeGetRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var expectedConf api.BackOfficeConfiguration
		expectedErr := errors.New("any error")
		e := MakeGetRealmBackOfficeConfigurationEndpoint(mockManagementComponent)
		req := map[string]string{prmRealm: realmName, prmQryGroupName: groupName}

		t.Run("Bad request", func(t *testing.T) {
			req[prmQryGroupName] = ""
			_, err := e(ctx, req)
			assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
		})
		t.Run("Success", func(t *testing.T) {
			req[prmQryGroupName] = groupName
			mockManagementComponent.EXPECT().GetRealmBackOfficeConfiguration(ctx, realmName, groupName).Return(expectedConf, expectedErr)
			res, err := e(ctx, req)
			assert.Equal(t, expectedErr, err)
			assert.Equal(t, expectedConf, res)
		})
	})

	t.Run("MakeUpdateRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var config api.BackOfficeConfiguration
		configJSON, _ := json.Marshal(config)
		req := map[string]string{prmRealm: realmName, prmQryGroupName: groupName}
		expectedErr := errors.New("update error")
		e := MakeUpdateRealmBackOfficeConfigurationEndpoint(mockManagementComponent)

		t.Run("Body is not a JSON value", func(t *testing.T) {
			req[reqBody] = `{]`
			_, err := e(ctx, req)
			assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
		})
		t.Run("Missing groupName", func(t *testing.T) {
			req[reqBody] = string(configJSON)
			req[prmQryGroupName] = ""
			_, err := e(ctx, req)
			assert.Equal(t, http.StatusBadRequest, err.(errorhandler.Error).Status)
		})
		t.Run("Success", func(t *testing.T) {
			req[prmQryGroupName] = groupName
			mockManagementComponent.EXPECT().UpdateRealmBackOfficeConfiguration(ctx, realmName, groupName, config).Return(expectedErr)
			res, err := e(ctx, req)
			assert.Equal(t, expectedErr, err)
			assert.Nil(t, res)
		})
	})

	t.Run("MakeGetUserRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		e := MakeGetUserRealmBackOfficeConfigurationEndpoint(mockManagementComponent)
		expectedResult := api.BackOfficeConfiguration{}
		req := map[string]string{prmRealm: realmName}
		ctx := context.TODO()
		mockManagementComponent.EXPECT().GetUserRealmBackOfficeConfiguration(ctx, realmName).Return(expectedResult, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, expectedResult, res)
	})
}

func TestGetRealmAdminConfigurationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetRealmAdminConfigurationEndpoint(mockManagementComponent)
	ctx := context.Background()

	t.Run("No error", func(t *testing.T) {
		realmName := "master"
		var adminConfig api.RealmAdminConfiguration
		req := make(map[string]string)
		req[prmRealm] = realmName

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})
	t.Run("Request fails at component level", func(t *testing.T) {
		realmName := "master"
		var adminConfig api.RealmAdminConfiguration
		expectedError := errors.New("component error")
		req := make(map[string]string)
		req[prmRealm] = realmName

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, expectedError)
		_, err := e(ctx, req)
		assert.Equal(t, expectedError, err)
	})
}

func TestUpdateRealmAdminConfigurationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeUpdateRealmAdminConfigurationEndpoint(mockManagementComponent)
	ctx := context.Background()

	t.Run("No error", func(t *testing.T) {
		realmName := "master"
		configJSON := `{"mode":"trustID"}`
		req := make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, gomock.Any()).Return(nil)
		res, err := e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid body content", func(t *testing.T) {
		realmName := "master"
		configJSON := `{}`
		req := make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("JSON error", func(t *testing.T) {
		realmName := "master"
		configJSON := `{`
		req := make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		res, err := e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetFederatedIdentitiesEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetFederatedIdentitiesEndpoint(mockManagementComponent)

	realm := "realm-name"
	userID := "user-id"
	ctx := context.Background()

	req := map[string]string{
		prmRealm:  realm,
		prmUserID: userID,
	}

	mockManagementComponent.EXPECT().GetFederatedIdentities(ctx, realm, userID).Return([]api.FederatedIdentityRepresentation{}, nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestLinkShadowUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeLinkShadowUserEndpoint(mockManagementComponent)

	realm := "master"
	ctx := context.Background()
	username := "username"
	userID := "abcdefgh-1234-ijkl-5678-mnopqrstuvwx"
	provider := "provider"

	req := make(map[string]string)
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
		req2 := map[string]string{reqBody: "JSON"}
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockManagementComponent := mock.NewManagementComponent(mockCtrl)

	e := MakeGetIdentityProvidersEndpoint(mockManagementComponent)

	realm := "master"
	ctx := context.Background()

	req := make(map[string]string)
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
