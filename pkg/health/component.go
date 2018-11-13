package health

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/pkg/errors"
)

// HealthCheckStorage is the interface of the module that stores the health reports
// in the DB.
type HealthCheckStorage interface {
	Read(ctx context.Context, module, healthcheck string) (json.RawMessage, error)
	Update(ctx context.Context, module string, jsonReports json.RawMessage, validity time.Duration) error
}

// HealthChecker is the interface of the health check modules.
type HealthChecker interface {
	HealthCheck(context.Context, string) (json.RawMessage, error)
}

// Component is the Health component.
type Component struct {
	healthCheckModules  map[string]HealthChecker
	healthCheckValidity map[string]time.Duration
	storage             HealthCheckStorage
}

// NewComponent returns the health component.
func NewComponent(healthCheckModules map[string]HealthChecker, healthCheckValidity map[string]time.Duration, storage HealthCheckStorage) *Component {
	return &Component{
		healthCheckModules:  healthCheckModules,
		healthCheckValidity: healthCheckValidity,
		storage:             storage,
	}
}

func (c *Component) HealthChecks(ctx context.Context, req map[string]string) (json.RawMessage, error) {
	var module = req["module"]

	ctx = filterContext(ctx)

	if module == "" {
		return c.allHealthChecks(ctx, req)
	}
	return c.healthCheck(ctx, module, req)
}

func (c *Component) allHealthChecks(ctx context.Context, req map[string]string) (json.RawMessage, error) {
	var useCache = true
	if req["nocache"] == "1" {
		useCache = false
	}

	var moduleNames = allKeys(c.healthCheckModules)
	sort.Strings(moduleNames)

	var reports = map[string]json.RawMessage{}
	for _, moduleName := range moduleNames {
		if useCache {
			var jsonReports, err = c.storage.Read(ctx, moduleName, "")
			if err == nil {
				reports[moduleName] = jsonReports
				continue
			}

			switch err {
			// By default, we return the error.
			default:
				return nil, err
			// If the error is ErrInvalid or ErrNotFound, we can recover by simply executing the health checks.
			case ErrInvalid, ErrNotFound:
			}
		}

		var module, ok = c.healthCheckModules[moduleName]
		if !ok {
			// Should not happen: there is a middleware validating the inputs.
			panic(fmt.Sprintf("Unknown health check module: %v", moduleName))
		}

		// Execute health check
		var jsonReports, err = module.HealthCheck(ctx, "")
		if err != nil {
			return nil, errors.Wrapf(err, "health checks for module %s failed", module)
		}

		reports[moduleName] = jsonReports

		// Store report
		c.storage.Update(ctx, moduleName, jsonReports, c.healthCheckValidity[moduleName])
	}

	var jsonReports json.RawMessage
	{
		var err error
		jsonReports, err = json.MarshalIndent(reports, "", "  ")
		if err != nil {
			return nil, errors.Wrap(err, "could not marshall all healthcheck reports")
		}
	}
	return jsonReports, nil
}

// Single health check
func (c *Component) healthCheck(ctx context.Context, moduleName string, req map[string]string) (json.RawMessage, error) {
	var healthCheck = req["healthcheck"]

	var useCache = true
	if req["nocache"] == "1" {
		useCache = false
	}

	if useCache {
		var report, err = c.storage.Read(ctx, moduleName, healthCheck)
		if err == nil {
			return report, err
		}

		switch err {
		// By default, we return the error.
		default:
			return nil, err
		// If the error is ErrInvalid or ErrNotFound, we can recover by simply executing the health checks.
		case ErrInvalid, ErrNotFound:
		}
	}

	var module, ok = c.healthCheckModules[moduleName]
	if !ok {
		// Should not happen: there is a middleware validating the inputs.
		panic(fmt.Sprintf("Unknown health check module: %v", moduleName))
	}

	// Execute health check
	var report, err = module.HealthCheck(ctx, healthCheck)
	if err != nil {
		return nil, err
	}

	// Store report
	c.storage.Update(ctx, moduleName, report, c.healthCheckValidity[moduleName])

	return report, err
}

func allKeys(m map[string]HealthChecker) []string {
	var keys = []string{}

	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

// The modules get a clean version of the context. This function create a new empty context
// and copy only the required keys into it.
func filterContext(ctx context.Context) context.Context {
	// New context for the modules
	var mctx = context.Background()

	mctx = context.WithValue(mctx, "correlation_id", ctx.Value("correlation_id").(string))

	return mctx
}
