package apistatistics

import (
	"database/sql"
	"testing"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestToConnRepresentation(t *testing.T) {
	var dbConn = DbConnectionRepresentation{
		Date:   sql.NullString{},
		Result: sql.NullString{},
		User:   sql.NullString{},
		IP:     "0.0.0.0",
	}
	assert.Equal(t, StatisticsConnectionRepresentation{IP: "0.0.0.0"}, dbConn.ToConnRepresentation())

	dbConn.Date = sql.NullString{String: "01/01/2020", Valid: true}
	assert.Equal(t, StatisticsConnectionRepresentation{Date: "01/01/2020", IP: "0.0.0.0"}, dbConn.ToConnRepresentation())
}

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
