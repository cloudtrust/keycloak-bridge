package keycloakb

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func createAuthSlice(auth configuration.Authorization, count int) []configuration.Authorization {
	var res []configuration.Authorization
	for idx := 0; idx < count; idx++ {
		res = append(res, auth)
	}
	return res
}

func TestTransaction(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockTx := mock.NewTransaction(mockCtrl)
	authTx := NewAuthorizationTransaction(mockTx)
	anError := errors.New("error")
	ctx := context.TODO()
	auth := configuration.Authorization{
		RealmID:         ptr("realm"),
		GroupName:       ptr("name"),
		Action:          ptr("action"),
		TargetRealmID:   ptr("target-realm"),
		TargetGroupName: ptr("target-group"),
	}

	t.Run("Close", func(t *testing.T) {
		t.Run("Failure", func(t *testing.T) {
			mockTx.EXPECT().Close().Return(anError)
			err := authTx.Close()
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockTx.EXPECT().Close().Return(nil)
			err := authTx.Close()
			assert.Nil(t, err)
		})
	})
	t.Run("Commit", func(t *testing.T) {
		t.Run("Failure", func(t *testing.T) {
			mockTx.EXPECT().Commit().Return(anError)
			err := authTx.Commit()
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockTx.EXPECT().Commit().Return(nil)
			err := authTx.Commit()
			assert.Nil(t, err)
		})
	})
	t.Run("CreateAuthorizations", func(t *testing.T) {
		t.Run("No authorization", func(t *testing.T) {
			err := authTx.CreateAuthorizations(ctx, []configuration.Authorization{})
			assert.Nil(t, err)
		})
		t.Run("Failure", func(t *testing.T) {
			authz := createAuthSlice(auth, 27)
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).DoAndReturn(func(_ string, args ...any) (sql.Result, error) {
				assert.Len(t, args, len(authz)*5)
				return nil, anError
			})
			err := authTx.CreateAuthorizations(ctx, authz)
			assert.NotNil(t, err)
		})
		t.Run("Failure in sub auth slice", func(t *testing.T) {
			authz := createAuthSlice(auth, 116)
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).DoAndReturn(func(_ string, args ...any) (sql.Result, error) {
				assert.Len(t, args, 50*5)
				return nil, anError
			})
			err := authTx.CreateAuthorizations(ctx, authz)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			authz := createAuthSlice(auth, 116)
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).DoAndReturn(func(_ string, args ...any) (sql.Result, error) {
				assert.Len(t, args, 50*5)
				return nil, nil
			}).Times(2)
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).DoAndReturn(func(_ string, args ...any) (sql.Result, error) {
				assert.Len(t, args, 16*5)
				return nil, nil
			})
			err := authTx.CreateAuthorizations(ctx, authz)
			assert.Nil(t, err)
		})
	})
	t.Run("RemoveAuthorizations", func(t *testing.T) {
		t.Run("No authorization", func(t *testing.T) {
			err := authTx.RemoveAuthorizations(ctx, []configuration.Authorization{})
			assert.Nil(t, err)
		})
		t.Run("Failure", func(t *testing.T) {
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil)
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, anError)
			err := authTx.RemoveAuthorizations(ctx, []configuration.Authorization{auth, auth, auth})
			assert.NotNil(t, err)
		})
		t.Run("One element success", func(t *testing.T) {
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil)
			err := authTx.RemoveAuthorizations(ctx, []configuration.Authorization{auth})
			assert.Nil(t, err)
		})
		t.Run("One element success", func(t *testing.T) {
			mockTx.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil).Times(3)
			err := authTx.RemoveAuthorizations(ctx, []configuration.Authorization{auth, auth, auth})
			assert.Nil(t, err)
		})
	})
}
