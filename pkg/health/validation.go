package health

import (
	"context"
	"encoding/json"
	"fmt"
)

// MakeValidationMiddleware makes a middleware that validate the health check module comming from
// the HTTP route.
func MakeValidationMiddleware(validValues map[string]struct{}) func(HealthCheckers) HealthCheckers {
	return func(next HealthCheckers) HealthCheckers {
		return &validationMW{
			validValues: validValues,
			next:        next,
		}
	}
}

type validationMW struct {
	validValues map[string]struct{}
	next        HealthCheckers
}

// ErrUnknownHCModule is the error returned when there is a health request for
// an unknown healthcheck module.
type ErrUnknownHCModule struct {
	s string
}

func (e *ErrUnknownHCModule) Error() string {
	return fmt.Sprintf("no health check module with name '%s'", e.s)
}

func (m *validationMW) HealthChecks(ctx context.Context, req map[string]string) (json.RawMessage, error) {
	// Check health check module validity.
	var module = req["module"]

	var _, ok = m.validValues[module]
	if !ok {
		return nil, &ErrUnknownHCModule{module}
	}

	return m.next.HealthChecks(ctx, req)
}
