// +build integration

package health_test

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	. "github.com/cloudtrust/flaki-service/pkg/health"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

var (
	hostPort = flag.String("hostport", "127.0.0.1:26257", "cockroach host:port")
	user     = flag.String("user", "cockroach", "user name")
	db       = flag.String("db", "health", "database name")
)

func TestIntNewStorageModule(t *testing.T) {
	var db = setupCleanDB(t)
	rand.Seed(time.Now().UnixNano())

	var (
		componentName = "flaki-service"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
	)

	// The table health does not exists.
	_, err := db.Exec("SELECT * from health")
	assert.NotNil(t, err)

	var _ = NewStorageModule(componentName, componentID, db)

	// NewStorageModule create table health.
	_, err = db.Exec("SELECT * from health")
	assert.Nil(t, err)
}

func TestIntRead(t *testing.T) {
	var db = setupCleanDB(t)
	rand.Seed(time.Now().UnixNano())

	var (
		componentName = "flaki-service"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
		unit          = "influx"
		reports       = json.RawMessage(`[{"name":"ping", "duration":"1s", "status":"OK", "error":"Error"}]`)
	)

	var m = NewStorageModule(componentName, componentID, db)

	// Read health checks report for 'influx', it should be empty now.
	var r, err = m.Read(unit)
	assert.Nil(t, err)
	fmt.Println(string(r.Reports))
	assert.Zero(t, len(r.Reports))

	// Save a health check report in DB.
	err = m.Update(unit, 10 * time.Second, reports)
	assert.Nil(t, err)

	// Read health checks report for 'influx', now there is one result.
	r, err = m.Read(unit)
	assert.Nil(t, err)

	var aaa []map[string]string
	json.Unmarshal(r.Reports, &aaa)
	assert.Equal(t, "ping", aaa[0]["name"])
	assert.Equal(t, "1s", aaa[0]["duration"])
	assert.Equal(t, "OK", aaa[0]["status"])
	assert.Equal(t, "Error", aaa[0]["error"])
}

func setupCleanDB(t *testing.T) *sql.DB {
	var db, err = sql.Open("postgres", fmt.Sprintf("postgresql://%s@%s/%s?sslmode=disable", *user, *hostPort, *db))
	assert.Nil(t, err)
	// Clean
	db.Exec("DROP table health")
	return db
}
