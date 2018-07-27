package health_test

//go:generate mockgen -destination=./mock/storage.go -package=mock -mock_names=Storage=Storage  github.com/cloudtrust/keycloak-bridge/pkg/health Storage

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

const (
	createHealthTblStmt = `
CREATE TABLE IF NOT EXISTS health (
	component_name STRING,
	component_id STRING,
	module STRING,
	healthcheck STRING,
	json JSONB,
	last_updated TIMESTAMPTZ,
	valid_until TIMESTAMPTZ,
PRIMARY KEY (component_name, component_id, module, healthcheck)
)`
	upsertHealthStmt = `
UPSERT INTO health (
	component_name,
	component_id,
	module,
	healthcheck,
	json, 
	last_updated,
	valid_until)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	selectHealthStmt = `SELECT * FROM health WHERE (component_name = $1 AND component_id = $2 AND unit = $3)`
	cleanHealthStmt  = `DELETE from health WHERE (component_name = $1 AND valid_until < $2)`
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestNewStorageModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStorage = mock.NewStorage(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
	)

	mockStorage.EXPECT().Exec(createHealthTblStmt).Return(nil, nil).Times(1)
	_ = NewStorageModule(componentName, componentID, mockStorage)
}

func TestUpdate(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStorage = mock.NewStorage(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
		module        = "cockroach"
		jsonReports   = reportIndent(json.RawMessage(`[{"name": "ping cockroach","status": "OK","duration": "1ms"}]`))
		jsonReport    = json.RawMessage(`{"duration":"1ms","name":"ping cockroach","status":"OK"}`)
		validity      = 1 * time.Minute
		ctx           = context.Background()
	)

	mockStorage.EXPECT().Exec(createHealthTblStmt).Return(nil, nil).Times(1)
	var m = NewStorageModule(componentName, componentID, mockStorage)

	mockStorage.EXPECT().Exec(upsertHealthStmt, componentName, componentID, module, "ping cockroach", string(jsonReport), gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
	var err = m.Update(ctx, module, jsonReports, validity)
	assert.Nil(t, err)
}

func TestUpdateFail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStorage = mock.NewStorage(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
		module        = "cockroach"
		jsonReports   = reportIndent(json.RawMessage(`[{"name": "ping cockroach","status": "OK","duration": "1ms"}]`))
		jsonReport    = json.RawMessage(`{"duration":"1ms","name":"ping cockroach","status":"OK"}`)
		validity      = 1 * time.Minute
		ctx           = context.Background()
	)

	mockStorage.EXPECT().Exec(createHealthTblStmt).Return(nil, nil).Times(1)
	var m = NewStorageModule(componentName, componentID, mockStorage)

	mockStorage.EXPECT().Exec(upsertHealthStmt, componentName, componentID, module, "ping cockroach", string(jsonReport), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("fail")).Times(1)
	var err = m.Update(ctx, module, jsonReports, validity)
	assert.NotNil(t, err)
}

const selectOneHealthStmt = `
SELECT * FROM health
WHERE (component_name = $1 AND component_id = $2 AND module = $3 AND healthcheck = $4)`

const selectAllHealthStmt = `
SELECT * FROM health
WHERE (component_name = $1 AND component_id = $2 AND module = $3)`

func TestRead(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStorage = mock.NewStorage(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
		module        = "cockroach"
		healthcheck   = "ping"
		ctx           = context.Background()
	)

	mockStorage.EXPECT().Exec(createHealthTblStmt).Return(nil, nil).Times(1)
	var m = NewStorageModule(componentName, componentID, mockStorage)

	mockStorage.EXPECT().Query(selectOneHealthStmt, componentName, componentID, module, healthcheck).Return(nil, nil).Times(1)
	var _, err = m.Read(ctx, module, healthcheck)
	assert.Equal(t, ErrNotFound, err)
}
