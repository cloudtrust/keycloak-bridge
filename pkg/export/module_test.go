package export

//go:generate mockgen -destination=./mock/keycloak.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/export KeycloakClient

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/export/mock"
	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestGetRealms(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloak = mock.NewKeycloakClient(mockCtrl)

	var m = NewModule(mockKeycloak)

	var (
		realm  = "realm"
		realm1 = "realm1"
		rr     = []keycloak.RealmRepresentation{{Realm: &realm}, {Realm: &realm1}}
	)

	{
		mockKeycloak.EXPECT().GetRealms().Return(rr, nil).Times(1)
		var realms, err = m.GetRealms(context.Background())
		assert.Nil(t, err)
		assert.Equal(t, realm, realms[0])
		assert.Equal(t, realm1, realms[1])
	}

	{
		mockKeycloak.EXPECT().GetRealms().Return(nil, fmt.Errorf("fail")).Times(1)
		var realms, err = m.GetRealms(context.Background())
		assert.NotNil(t, err)
		assert.Equal(t, []string{}, realms)
	}
}

func TestExportRealm(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloak = mock.NewKeycloakClient(mockCtrl)

	var m = NewModule(mockKeycloak)

	var (
		realmName = "realm"
		rr        = keycloak.RealmRepresentation{Realm: &realmName}
	)

	{
		mockKeycloak.EXPECT().ExportRealm(realmName).Return(rr, nil).Times(1)
		var realm, err = m.ExportRealm(context.Background(), realmName)
		assert.Nil(t, err)
		assert.Equal(t, realmName, *realm.Realm)
	}

	{
		mockKeycloak.EXPECT().ExportRealm(realmName).Return(keycloak.RealmRepresentation{}, fmt.Errorf("fail")).Times(1)
		var realm, err = m.ExportRealm(context.Background(), realmName)
		assert.NotNil(t, err)
		assert.Equal(t, keycloak.RealmRepresentation{}, realm)
	}
}
