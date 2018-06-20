package export

import (
	"context"

	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
)

// KeycloakClient is the interface of the keycloak client.
type KeycloakClient interface {
	GetRealms() ([]keycloak.RealmRepresentation, error)
	ExportRealm(realmName string) (keycloak.RealmRepresentation, error)
}

type Module struct {
	kc KeycloakClient
}

// NewModule returns a user module.
func NewModule(kc KeycloakClient) *Module {
	return &Module{
		kc: kc,
	}
}

// GetRealms returns the list of all realms.
func (m *Module) GetRealms(ctx context.Context) ([]string, error) {
	var res = []string{}
	var realms, err = m.kc.GetRealms()
	if err != nil {
		return res, errors.Wrap(err, "could not get list of realms")
	}

	for _, realm := range realms {
		if name := realm.Realm; name != nil {
			res = append(res, *name)
		}
	}
	return res, nil
}

// ExportRealm exports the desired realm.
func (m *Module) ExportRealm(ctx context.Context, realmName string) (keycloak.RealmRepresentation, error) {
	return m.kc.ExportRealm(realmName)
}
