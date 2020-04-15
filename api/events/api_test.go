package apievents

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToAuditRepresentation(t *testing.T) {
	var dba = DbAuditRepresentation{
		AuditID:        45,
		AuditTime:      46,
		Origin:         sql.NullString{String: "Origin", Valid: true},
		AdditionalInfo: sql.NullString{String: "Additional", Valid: false},
	}
	var audit = dba.ToAuditRepresentation()

	assert.Equal(t, "Origin", audit.Origin)
	assert.Equal(t, "", audit.AdditionalInfo)
}
