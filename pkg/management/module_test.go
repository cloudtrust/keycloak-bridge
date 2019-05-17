package management

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestConfigurationDBModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewDBConfiguration(mockCtrl)

	mockDB.EXPECT().Exec(gomock.Any()).Return(nil, nil).Times(1)
	mockDB.EXPECT().Exec(gomock.Any(), "realmId", gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
	var configDBModule = NewConfigurationDBModule(mockDB)
	var err = configDBModule.StoreOrUpdate(context.Background(), "realmId", "{}")
	assert.Nil(t, err)
}
