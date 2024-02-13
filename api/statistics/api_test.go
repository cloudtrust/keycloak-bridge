package apistatistics

import (
	"testing"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func TestConvertToAPIStatisticsUsers(t *testing.T) {
	var stats = kc.StatisticsUsersRepresentation{
		Total:    1,
		Disabled: 2,
		Inactive: 3,
	}
	var expected = StatisticsUsersRepresentation{
		Total:    1,
		Disabled: 2,
		Inactive: 3,
	}
	assert.Equal(t, expected, ConvertToAPIStatisticsUsers(stats))
}
