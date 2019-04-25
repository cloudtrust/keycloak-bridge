package keycloakb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPResponse(t *testing.T) {
	// Coverage
	var kcError = CreateMissingParameterError("parameter")
	assert.Contains(t, kcError.Error(), kcError.Message)
}
