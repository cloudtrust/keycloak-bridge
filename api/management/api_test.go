package management_api

import (
	"testing"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestConvertCredential(t *testing.T) {
	var credKc kc.CredentialRepresentation
	var credType = "password"
	var credID = "123456"
	var configKc map[string][]string
	configKc = make(map[string][]string)
	configKc["undesired_Key"] = make([]string, 0)
	configKc["deviceInfo_Model"] = make([]string, 0)

	credKc.Type = &credType
	credKc.Id = &credID
	credKc.Config = nil

	assert.Equal(t, credKc.Type, ConvertCredential(&credKc).Type)
	assert.Equal(t, credKc.Id, ConvertCredential(&credKc).Id)
	assert.Nil(t, ConvertCredential(&credKc).Config)

	credKc.Config = &configKc
	assert.NotNil(t, ConvertCredential(&credKc).Config)
	assert.Equal(t, 1, len(*ConvertCredential(&credKc).Config))
}
