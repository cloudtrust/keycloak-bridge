package keycloakb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddPendingCheck(t *testing.T) {
	var res, err = AddPendingCheck(nil, "check-1")
	assert.Nil(t, err)
	assert.Contains(t, *res, "check-1")

	var input = "{"
	res, err = AddPendingCheck(&input, "check-1")
	assert.Equal(t, ErrCantUnmarshalPendingCheck, err)
	assert.Contains(t, *res, "check-1")
}

func TestPendingChecks(t *testing.T) {
	t.Run("Invalid input case", func(t *testing.T) {
		var input = "{"
		var pc, err = NewPendingChecks(&input)
		assert.Equal(t, ErrCantUnmarshalPendingCheck, err)
		assert.NotNil(t, pc)
		assert.Nil(t, pc.ToAttribute())
	})
	t.Run("Nil case", func(t *testing.T) {
		var pc, err = NewPendingChecks(nil)
		assert.Nil(t, err)

		pc.RemovePendingCheck("unknown")
		assert.Nil(t, pc.ToAttribute())
		assert.Nil(t, pc.ToCheckNames())
	})
	var txtValue *string
	t.Run("Add pending check", func(t *testing.T) {
		var pc, _ = NewPendingChecks(nil)
		pc.AddPendingCheck("check-1")
		pc.AddPendingCheck("check-2")

		txtValue = pc.ToAttribute()
		assert.NotNil(t, txtValue)
		assert.Contains(t, *txtValue, "check-1")
		assert.Contains(t, *txtValue, "check-2")
		assert.Contains(t, *pc.ToCheckNames(), "check-1")
		assert.Contains(t, *pc.ToCheckNames(), "check-2")
	})
	t.Run("Remove one", func(t *testing.T) {
		var pc, err = NewPendingChecks(txtValue)
		assert.Nil(t, err)

		pc.RemovePendingCheck("check-2")
		var txtValueWhenRemoved = pc.ToAttribute()
		assert.NotNil(t, txtValueWhenRemoved)
		assert.Contains(t, *txtValueWhenRemoved, "check-1")
		assert.NotContains(t, *txtValueWhenRemoved, "check-2")
	})
	t.Run("Remove all", func(t *testing.T) {
		var pc, err = NewPendingChecks(txtValue)
		assert.Nil(t, err)

		pc.RemovePendingCheck("check-3")
		pc.RemovePendingCheck("check-1")
		pc.RemovePendingCheck("check-2")
		assert.Nil(t, pc.ToAttribute())
	})
}
