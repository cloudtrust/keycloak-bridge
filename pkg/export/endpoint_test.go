package export

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/export/mock"
	keycloak "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestExportEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeExportEndpoint(mockComponent)

	var (
		realms = []string{"master", "test", "internal"}
		reply  = map[string]interface{}{
			"master":   keycloak.RealmRepresentation{Realm: &realms[0]},
			"test":     keycloak.RealmRepresentation{Realm: &realms[1]},
			"internal": keycloak.RealmRepresentation{Realm: &realms[2]},
		}
		ctx = context.Background()
	)

	mockComponent.EXPECT().Export(ctx).Return(reply, nil).Times(1)
	var res, err = e(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, reply, res)
}

func TestStoreAndExportEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeStoreAndExportEndpoint(mockComponent)

	var (
		realms = []string{"master", "test", "internal"}
		reply  = map[string]interface{}{
			"master":   keycloak.RealmRepresentation{Realm: &realms[0]},
			"test":     keycloak.RealmRepresentation{Realm: &realms[1]},
			"internal": keycloak.RealmRepresentation{Realm: &realms[2]},
		}
		ctx = context.Background()
	)

	mockComponent.EXPECT().StoreAndExport(ctx).Return(reply, nil).Times(1)
	var res, err = e(ctx, nil)
	assert.Nil(t, err)
	assert.Equal(t, reply, res)
}
