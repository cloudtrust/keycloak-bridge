package constants

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func matches(regex string, value string) bool {
	var res, _ = regexp.MatchString(regex, value)
	return res
}

func TestInit(t *testing.T) {
	var tests = map[string]func() string{
		"first-name":     func() string { return RegExpFirstName },
		"last-name":      func() string { return RegExpLastName },
		"country-code":   func() string { return RegExpCountryCode },
		"birth-location": func() string { return RegExpBirthLocation },
		"id-doc-number":  func() string { return RegExpIDDocumentNumber },
	}
	var newRegex = "^.+$"
	for k, v := range tests {
		var original = v()
		InitializeRegexOverride(map[string]string{k: newRegex})
		assert.NotEqual(t, original, v())

		InitializeRegexOverride(map[string]string{k: original})
		assert.Equal(t, original, v())
	}
}

func TestRegex(t *testing.T) {
	assert.True(t, matches(RegExpFirstName, "CLÉMENT, ROMAIN, HUGO"))
	assert.False(t, matches(RegExpFirstName, ",LÉMENT, ROMAIN, HUGO"))

	assert.True(t, matches(RegExpBirthLocation, "àáâäçèéêëìíîïñòóôöùúûüßÀÁÂÄÇÈÉÊËÌÍÎÏÑÒÓÔÖÙÚÛÜÆæŒœ"))
	assert.True(t, matches(RegExpBirthLocation, "Wrocław"))
	assert.True(t, matches(RegExpBirthLocation, "Владивосток"))
	assert.True(t, matches(RegExpBirthLocation, "Lausanne"))
	assert.True(t, matches(RegExpBirthLocation, "Lausanne VD"))
	assert.True(t, matches(RegExpBirthLocation, "Lausanne/VD"))
	assert.True(t, matches(RegExpBirthLocation, "ABRANTES * SANTAREM"))
	assert.True(t, matches(RegExpBirthLocation, "Vully-les-lacs (c'est ou)"))
	assert.True(t, matches(RegExpBirthLocation, "MUN.BURUREŞTI SEC. 1"))
	assert.False(t, matches(RegExpBirthLocation, "Lausanne#VD"))
}
