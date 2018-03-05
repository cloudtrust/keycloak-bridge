package main

import (
	sentry "github.com/getsentry/raven-go"
)

// Sentry is the interface of the NOOP Sentry.
type Sentry interface {
	URL() string
}

// NoopSentry is a sentry client that does nothing.
type NoopSentry struct{}

// CaptureError does nothing for the receiver NoopSentry.
func (s *NoopSentry) CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string {
	return ""
}

// URL does nothing for the receiver NoopSentry.
func (s *NoopSentry) URL() string { return "" }

// Close does nothing for the receiver NoopSentry.
func (s *NoopSentry) Close() {}
