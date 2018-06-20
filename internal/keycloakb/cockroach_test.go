package keycloakb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoopCockroach(t *testing.T) {
	var c = NoopCockroach{}

	// Exec
	{
		res, err := c.Exec("")
		assert.Nil(t, err)
		assert.Zero(t, res)

		i, err := res.LastInsertId()
		assert.Nil(t, err)
		assert.Zero(t, i)

		i, err = res.RowsAffected()
		assert.Nil(t, err)
		assert.Zero(t, i)
	}

	// Query
	{
		res, err := c.Query("")
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// QueryRow
	{
		res := c.QueryRow("")
		assert.Nil(t, res)
	}
}
