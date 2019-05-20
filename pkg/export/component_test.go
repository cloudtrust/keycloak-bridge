package export

import (
	"context"
	"encoding/json"
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

type config struct {
	Name    string
	Version string
	Realms  []string
}

func TestExport(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockRealmExporter = mock.NewRealmExporter(mockCtrl)
	var mockStorage = mock.NewStorage(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		version       = "1.0"
		realms        = []string{"master", "test", "internal"}
	)
	var c = NewComponent(componentName, version, mockRealmExporter, mockStorage)

	var data, err = json.Marshal(config{
		Name:    componentName,
		Version: version,
		Realms:  realms,
	})
	assert.Nil(t, err)

	mockStorage.EXPECT().Read(componentName, version).Return(data, nil).Times(1)

	res, err := c.Export(context.Background())
	assert.Nil(t, err)

	assert.Equal(t, componentName, res["Name"])
	assert.Equal(t, version, res["Version"])
	for _, n := range realms {
		assert.Contains(t, res["Realms"], n)
	}
}

func TestStoreAndExport(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockRealmExporter = mock.NewRealmExporter(mockCtrl)
	var mockStorage = mock.NewStorage(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		version       = "1.0"
		realms        = []string{"master", "test", "internal"}
		ctx           = context.Background()
		rr            = []keycloak.RealmRepresentation{{Realm: &realms[0]}, {Realm: &realms[1]}, {Realm: &realms[2]}}
	)
	var c = NewComponent(componentName, version, mockRealmExporter, mockStorage)

	var realmMap = map[string]interface{}{
		"master":   rr[0],
		"test":     rr[1],
		"internal": rr[2],
	}
	var data, err = json.Marshal(realmMap)
	assert.Nil(t, err)

	mockRealmExporter.EXPECT().GetRealms(ctx).Return(realms, nil).Times(1)
	mockRealmExporter.EXPECT().ExportRealm(ctx, realms[0]).Return(rr[0], nil).Times(1)
	mockRealmExporter.EXPECT().ExportRealm(ctx, realms[1]).Return(rr[1], nil).Times(1)
	mockRealmExporter.EXPECT().ExportRealm(ctx, realms[2]).Return(rr[2], nil).Times(1)
	mockStorage.EXPECT().Save(componentName, version, data).Return(nil).Times(1)

	res, err := c.StoreAndExport(ctx)
	assert.Nil(t, err)

	assert.Equal(t, "master", *res["master"].(keycloak.RealmRepresentation).Realm)
	assert.Equal(t, "test", *res["test"].(keycloak.RealmRepresentation).Realm)
	assert.Equal(t, "internal", *res["internal"].(keycloak.RealmRepresentation).Realm)

}
