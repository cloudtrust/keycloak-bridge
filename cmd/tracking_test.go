package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoopSentry(t *testing.T) {
	var noopSentry = &NoopSentry{}

	// CaptureError
	assert.Zero(t, noopSentry.CaptureError(nil, nil))
	assert.Zero(t, noopSentry.CaptureError(fmt.Errorf("fail"), map[string]string{"key": "val"}))

	// URL
	assert.Zero(t, noopSentry.URL())
}
