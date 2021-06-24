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

func TestRegex(t *testing.T) {
	assert.True(t, matches(RegExpBirthLocation, "Lausanne"))
	assert.True(t, matches(RegExpBirthLocation, "Lausanne VD"))
	assert.True(t, matches(RegExpBirthLocation, "Lausanne/VD"))
	assert.True(t, matches(RegExpBirthLocation, "Vully-les-lacs (c'est ou)"))
	assert.False(t, matches(RegExpBirthLocation, "Lausanne#VD"))
}
