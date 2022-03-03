package apisupport

import (
	"testing"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func TestConvertToEmailInfo(t *testing.T) {
	var realm1 = "realm1"
	var date1 int64 = 123456789
	var input = []kc.EmailInfoRepresentation{{RealmName: &realm1, CreationDate: &date1}}
	var output = ConvertToEmailInfo(input)
	assert.Len(t, output, 1)
	assert.Equal(t, realm1, *output[0].Realm)
	assert.Equal(t, date1, *output[0].CreationDate)
}
