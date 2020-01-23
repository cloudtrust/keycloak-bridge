package keycloakb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateParameterIn(t *testing.T) {
	var allowedValues = map[string]bool{"monday": true, "tuesday": true, "friday": true}
	var valid = "tuesday"
	var invalid = "wednesday"

	assert.NotNil(t, ValidateParameterIn("element", nil, allowedValues, true))
	assert.Nil(t, ValidateParameterIn("element", nil, allowedValues, false))

	assert.NotNil(t, ValidateParameterIn("element", &invalid, allowedValues, true))
	assert.Nil(t, ValidateParameterIn("element", &valid, allowedValues, true))
}

func TestValidateParameterPhoneNumber(t *testing.T) {
	var valid = "+41235678901"
	var invalid = valid + "0"

	assert.NotNil(t, ValidateParameterPhoneNumber("element", nil))
	assert.NotNil(t, ValidateParameterPhoneNumber("element", &invalid))
	assert.Nil(t, ValidateParameterPhoneNumber("element", &valid))
}

func TestValidateParameterRegExp(t *testing.T) {
	var regexp = `^\d+-\w+$`
	var valid = "456-abc"
	var invalid = "abc-456"

	assert.NotNil(t, ValidateParameterRegExp("element", nil, regexp, true))
	assert.Nil(t, ValidateParameterRegExp("element", nil, regexp, false))

	assert.NotNil(t, ValidateParameterRegExp("element", &invalid, regexp, true))
	assert.Nil(t, ValidateParameterRegExp("element", &valid, regexp, true))
}

func TestValidateParameterDate(t *testing.T) {
	var invalidDate = "29.02.2019"
	var validDate = "29.02.2020"
	var dateLayout = "02.01.2006"

	assert.NotNil(t, ValidateParameterDate("date", nil, dateLayout, true))
	assert.Nil(t, ValidateParameterDate("date", nil, dateLayout, false))

	assert.NotNil(t, ValidateParameterDate("date", &invalidDate, dateLayout, true))
	assert.Nil(t, ValidateParameterDate("date", &validDate, dateLayout, true))
}
