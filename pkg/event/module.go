package event

import (
	"context"

	"github.com/cloudtrust/common-service/metrics"
	"github.com/go-kit/kit/log"
	influx "github.com/influxdata/influxdb/client/v2"
)

// ConsoleModule is the interface of the console module.
type ConsoleModule interface {
	Print(context.Context, map[string]string) error
}

type consoleModule struct {
	logger log.Logger
}

// NewConsoleModule returns a Console module.
func NewConsoleModule(logger log.Logger) ConsoleModule {
	return &consoleModule{
		logger: logger,
	}
}

func (cm *consoleModule) Print(_ context.Context, m map[string]string) error {
	// Log
	for k, v := range m {
		cm.logger.Log(k, v)
	}
	return nil
}

// StatisticModule is the interface of the keycloak statistic module.
type StatisticModule interface {
	Stats(context.Context, map[string]string) error
}

// Influx is the influx DB interface.
type Influx interface {
	Write(bp influx.BatchPoints) error
	Close()
}

type statisticModule struct {
	influx metrics.Metrics
}

//NewStatisticModule returns a Statistic module.
func NewStatisticModule(influx metrics.Metrics) StatisticModule {
	return &statisticModule{
		influx: influx,
	}
}

func (sm *statisticModule) Stats(ctx context.Context, m map[string]string) error {
	// Create a point and add to batch
	var tags = map[string]string{"type": m["type"], "realm": m["realmId"], "userId": m["userId"]}
	var fields = map[string]interface{}{
		"uid": m["uid"],
	}
	return sm.influx.Stats(ctx, "event_statistics", tags, fields)
}

const (
	createTable = `CREATE TABLE IF NOT EXISTS audit (
		audit_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		audit_time TIMESTAMP NULL,
		origin VARCHAR(255),
		realm_name VARCHAR(255),
		agent_user_id VARCHAR(36),
		agent_username VARCHAR(255),
		agent_realm_name VARCHAR(255),
		user_id VARCHAR(36),
		username VARCHAR(255),
		ct_event_type VARCHAR(50),
		kc_event_type VARCHAR(50),
		kc_operation_type VARCHAR(50),
		client_id VARCHAR(255),
		additional_info TEXT,
		CONSTRAINT audit_pk PRIMARY KEY (audit_id)
	  );`

	insertEvent = `INSERT INTO audit (
		audit_time,
		origin,
		realm_name,
		agent_user_id,
		agent_username,
		agent_realm_name,
		user_id,
		username,
		ct_event_type,
		kc_event_type,
		kc_operation_type,
		client_id,
		additional_info) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
)
