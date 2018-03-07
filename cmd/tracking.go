package main

import (
	sentry "github.com/getsentry/raven-go"
)

// Sentry is the Sentry client interface.
type Sentry interface {
	URL() string
}

// NoopSentry is a Sentry client that does nothing.
type NoopSentry struct{}

// CaptureError does nothing.
func (s *NoopSentry) CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string {
	return ""
}

// URL does nothing.
func (s *NoopSentry) URL() string { return "" }

// Close does nothing.
func (s *NoopSentry) Close() {}
