package export

import (
	"context"

	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
)

// KeycloakClient is the interface of the keycloak client.
type KeycloakClient interface {
	GetRealms(accessToken string) ([]keycloak.RealmRepresentation, error)
	ExportRealm(accessToken string, realmName string) (keycloak.RealmRepresentation, error)
}

// Module wraps a KeycloakClient to Get/Export realms
type Module struct {
	kc     KeycloakClient
	logger internal.Logger
}

// NewModule returns a user module.
func NewModule(kc KeycloakClient, logger internal.Logger) *Module {
	return &Module{
		kc:     kc,
		logger: logger,
	}
}

// GetRealms returns the list of all realms.
func (m *Module) GetRealms(ctx context.Context) ([]string, error) {
	var res = []string{}
	var accessToken = "TOKEN=="
	var realms, err = m.kc.GetRealms(accessToken)
	if err != nil {
		m.logger.Warn("err", err.Error())
		return res, errors.Wrap(err, internal.MsgErrCannotObtain+internal.ListOfRealms)
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
	var accessToken = "TOKEN=="
	res, err := m.kc.ExportRealm(accessToken, realmName)

	if err != nil {
		m.logger.Warn("err", err.Error())
		return keycloak.RealmRepresentation{}, err
	}

	return res, nil
}
