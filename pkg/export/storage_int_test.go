// +build integration

package export

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

var (
	hostPort = flag.String("hostport", "127.0.0.1:26257", "cockroach host:port")
	user     = flag.String("user", "cockroach", "user name")
	db       = flag.String("db", "config", "database name")
)

func TestIntNewStorageModule(t *testing.T) {
	var db = setupCleanDB(t)
	rand.Seed(time.Now().UnixNano())

	_, err := db.Exec("SELECT * from config")
	assert.NotNil(t, err)

	var _ = NewConfigStorageModule(db)

	_, err = db.Exec("SELECT * from config")
	assert.Nil(t, err)
}

type config struct {
	Name    string
	Version string
	Realms  []string
}

func TestSaveConfig(t *testing.T) {
	var db = setupCleanDB(t)

	var (
		componentName = "keycloak-service"
		version       = "1.0"
	)
	var config, err = json.Marshal(config{
		Name:    "name",
		Version: "1.0",
		Realms:  []string{"master", "test", "internal"},
	})
	assert.Nil(t, err)
	var s = NewConfigStorageModule(db)

	err = s.Save(componentName, version, config)
	assert.Nil(t, err)
}

func TestReadConfig(t *testing.T) {
	var db = setupCleanDB(t)

	var (
		componentName = "keycloak-service"
		version       = "1.0"
	)

	var c, err = json.Marshal(config{
		Name:    "name",
		Version: "1.0",
		Realms:  []string{"master", "test", "internal"},
	})
	assert.Nil(t, err)

	var s = NewConfigStorageModule(db)

	// Save config
	err = s.Save(componentName, version, c)
	assert.Nil(t, err)

	// Read config
	data, err := s.Read(componentName, version)
	assert.Nil(t, err)

	var cfg = config{}
	err = json.Unmarshal(data, &cfg)
	assert.Nil(t, err)
	assert.Equal(t, "name", cfg.Name)
	assert.Equal(t, "1.0", cfg.Version)
	assert.Equal(t, []string{"master", "test", "internal"}, cfg.Realms)
}

func setupCleanDB(t *testing.T) *sql.DB {
	var db, err = sql.Open("postgres", fmt.Sprintf("postgresql://%s@%s/%s?sslmode=disable", *user, *hostPort, *db))
	assert.Nil(t, err)
	// Clean
	db.Exec("DROP table config")
	return db
}
