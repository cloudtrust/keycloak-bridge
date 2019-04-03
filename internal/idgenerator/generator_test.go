package idgenerator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIDGenerator(t *testing.T) {
	var componentName = "bridge"
	var componentID = "123456"

	var generator = New(componentName, componentID)

	assert.NotEqual(t, generator.NextID(), generator.NextID())
	assert.Regexp(t, componentName+"-"+componentID+"-[0-9]{10}-[0-9]{20}", generator.NextID())
}
