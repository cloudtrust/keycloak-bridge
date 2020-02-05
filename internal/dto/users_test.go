package dto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLastValidation(t *testing.T) {
	var user = DBUser{}

	t.Run("No validation", func(t *testing.T) {
		user.Validations = nil
		assert.Nil(t, user.LastValidation())
	})

	t.Run("Has validation", func(t *testing.T) {
		var date1, _ = time.Parse(dateLayout, "01.01.2015")
		var date2, _ = time.Parse(dateLayout, "01.01.2018")
		user.Validations = []DBValidation{
			DBValidation{Date: &date1},
			DBValidation{Date: &date2},
		}
		assert.Equal(t, "01.01.2018", *user.LastValidation())
	})
}
