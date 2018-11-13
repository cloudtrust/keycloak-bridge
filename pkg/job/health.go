package job

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cloudtrust/go-jobs/job"
	"github.com/go-kit/kit/log"
)

// Storage is the interface of the module that stores the health reports
// in the DB.
type Storage interface {
	Update(ctx context.Context, module string, jsonReports json.RawMessage, validity time.Duration) error
	Clean() error
}

// Flaki is the interface of the IDs generator.
type Flaki interface {
	NextValidIDString() string
}

// HealthChecker is the interface of the health check modules.
type HealthChecker interface {
	HealthCheck(context.Context, string) (json.RawMessage, error)
}

// MakeHealthJob creates the job that periodically executes the health checks and save the result in DB.
func MakeHealthJob(module HealthChecker, moduleName string, healthCheckValidity time.Duration, storage Storage, logger log.Logger) (*job.Job, error) {
	var step1 = func(ctx context.Context, _ interface{}) (interface{}, error) {
		defer func(begin time.Time) {
			logger.Log("correlation_id", ctx.Value("correlation_id").(string), "healthcheckJob", moduleName, "step", "execute health check", "took", time.Since(begin))
		}(time.Now())

		return module.HealthCheck(ctx, "")
	}

	var step2 = func(ctx context.Context, r interface{}) (interface{}, error) {
		defer func(begin time.Time) {
			logger.Log("correlation_id", ctx.Value("correlation_id").(string), "healthcheckJob", moduleName, "step", "store health check", "took", time.Since(begin))
		}(time.Now())

		var jsonReports, ok = r.(json.RawMessage)
		if !ok {
			return nil, fmt.Errorf("health report should be a json.Rawmessage not %T", r)
		}

		var err = storage.Update(ctx, moduleName, jsonReports, healthCheckValidity)

		return nil, err
	}
	return job.NewJob(moduleName, job.Steps(step1, step2))
}

// MakeStorageCleaningJob creates the job that periodically clean the DB from the outdated health check reports.
func MakeStorageCleaningJob(storage Storage, logger log.Logger) (*job.Job, error) {
	var clean = func(context.Context, interface{}) (interface{}, error) {
		logger.Log("step", "clean")
		return nil, storage.Clean()
	}
	return job.NewJob("clean", job.Steps(clean))
}

// err return the string error that will be in the health report
func err(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
