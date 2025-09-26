package components

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/components"
	"github.com/cloudtrust/keycloak-bridge/pkg/components/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetComponentsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockCompComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetComponentsEndpoint(mockCompComponent)

	var realm = "test-community"
	var providerType = "org.keycloak.services.ui.extend.UiTabProvider"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealmName] = realm
	req[prmQryType] = providerType

	mockCompComponent.EXPECT().GetComponents(ctx, realm, &providerType).Return([]api.ComponentRepresentation{}, nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestCreateComponentEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockCompComponent = mock.NewComponent(mockCtrl)

	var e = MakeCreateComponentEndpoint(mockCompComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealmName] = realm

	comp := testApiComp()
	compJSON, _ := json.Marshal(comp)
	req[reqBody] = string(compJSON)

	mockCompComponent.EXPECT().CreateComponent(ctx, realm, comp).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestUpdateComponentEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockCompComponent = mock.NewComponent(mockCtrl)

	var e = MakeUpdateComponentEndpoint(mockCompComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealmName] = realm
	req[prmComponentID] = compID

	comp := testApiComp()
	compJSON, _ := json.Marshal(comp)
	req[reqBody] = string(compJSON)

	mockCompComponent.EXPECT().UpdateComponent(ctx, realm, compID, comp).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}
