package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNoopMetrics(t *testing.T) {
	var noopMetrics = &NoopMetrics{}

	var duration, s, err = noopMetrics.Ping(1 * time.Second)

	assert.Equal(t, time.Duration(0), duration)
	assert.Equal(t, "NOOP", s)
	assert.Nil(t, err)
}
