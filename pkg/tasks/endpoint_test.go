package tasks

import (
	"context"
	"errors"
	"testing"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/keycloak-bridge/pkg/tasks/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockTasksComponent := mock.NewComponent(mockCtrl)
	endpoint := MakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint(mockTasksComponent)

	ctx := context.TODO()
	var request interface{}

	t.Run("Error", func(t *testing.T) {
		anyError := errors.New("any error")
		mockTasksComponent.EXPECT().CleanUpAccordingToExpiredTermsOfUseAcceptance(gomock.Any()).Return(anyError)
		_, err := endpoint(ctx, request)
		assert.NotNil(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		mockTasksComponent.EXPECT().CleanUpAccordingToExpiredTermsOfUseAcceptance(gomock.Any()).Return(nil)
		res, err := endpoint(ctx, request)
		assert.Nil(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, commonhttp.StatusNoContent{}, res)
	})
}
