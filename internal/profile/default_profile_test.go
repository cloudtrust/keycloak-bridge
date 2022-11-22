package profile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultProfile(t *testing.T) {
	var profile, err = DefaultProfile("realm")
	assert.Nil(t, err)
	assert.Equal(t, "username", *profile.Attributes[0].Name)
}
