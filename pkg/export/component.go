package export

import (
	"context"
	"encoding/json"

	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
)

type component struct {
	componentName    string
	componentVersion string
	re               RealmExporter
	s                Storage
}

// RealmExporter interface
type RealmExporter interface {
	GetRealms(ctx context.Context) ([]string, error)
	ExportRealm(ctx context.Context, realmName string) (keycloak.RealmRepresentation, error)
}

// Storage interface
type Storage interface {
	Save(componentName, version string, config []byte) error
	Read(componentName, version string) ([]byte, error)
}

// NewComponent returns an export component.
func NewComponent(componentName, componentVersion string, re RealmExporter, s Storage) Component {
	return &component{
		componentName:    componentName,
		componentVersion: componentVersion,
		re:               re,
		s:                s,
	}
}

// Export reads the config data in DB and returns it.
func (c *component) Export(ctx context.Context) (map[string]interface{}, error) {
	var data, err = c.s.Read(c.componentName, c.componentVersion)
	if err != nil {
		return nil, err
	}
	var res = map[string]interface{}{}

	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// StoreAndExport export the config from keycloak, stores it in DB and returns it.
func (c *component) StoreAndExport(ctx context.Context) (map[string]interface{}, error) {
	var realms []string
	{
		var err error
		realms, err = c.re.GetRealms(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "export failed, could not get keycloak realms")
		}
	}

	var realmsMap = map[string]interface{}{}
	for _, r := range realms {
		var realm, err = c.re.ExportRealm(ctx, r)
		if err == nil {
			realmsMap[r] = realm
		} else {
			realmsMap[r] = err.Error()
		}
	}

	// Store
	var data, err = json.Marshal(realmsMap)
	if err != nil {
		return nil, errors.Wrapf(err, "component %s with version %s, could not marshal config", c.componentName, c.componentVersion)
	}

	err = c.s.Save(c.componentName, c.componentVersion, data)

	if err != nil {
		return nil, errors.Wrapf(err, "component %s with version %s, could not save config in db", c.componentName, c.componentVersion)
	}

	return realmsMap, nil
}
