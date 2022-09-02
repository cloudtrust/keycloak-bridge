package tasks

import (
	"context"
	"errors"
	"testing"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/keycloak-bridge/pkg/tasks/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockTasksComponent = mock.NewComponent(mockCtrl)
	var endpoint = MakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint(mockTasksComponent)

	var ctx = context.TODO()
	var request interface{}

	t.Run("Error", func(t *testing.T) {
		var anyError = errors.New("any error")
		mockTasksComponent.EXPECT().CleanUpAccordingToExpiredTermsOfUseAcceptance(gomock.Any()).Return(anyError)
		var _, err = endpoint(ctx, request)
		assert.NotNil(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		mockTasksComponent.EXPECT().CleanUpAccordingToExpiredTermsOfUseAcceptance(gomock.Any()).Return(nil)
		var res, err = endpoint(ctx, request)
		assert.Nil(t, err)
		assert.NotNil(t, res)
		assert.Equal(t, commonhttp.StatusNoContent{}, res)
	})
}
