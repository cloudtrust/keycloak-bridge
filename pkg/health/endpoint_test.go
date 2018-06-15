package health_test

//go:generate mockgen -destination=./mock/healthchecker.go -package=mock -mock_names=HealthChecker=HealthChecker github.com/cloudtrust/keycloak-bridge/pkg/health HealthChecker

import (
	"context"
	"encoding/json"
	"testing"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestInfluxHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var e = MakeExecInfluxHealthCheckEndpoint(mockComponent)
	var r = MakeReadInfluxHealthCheckEndpoint(mockComponent)

	//Exec
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ExecInfluxHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = e(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}

	//Read
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ReadInfluxHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = r(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}
}

func TestJaegerHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var e = MakeExecJaegerHealthCheckEndpoint(mockComponent)
	var r = MakeReadJaegerHealthCheckEndpoint(mockComponent)

	//Exec
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ExecJaegerHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = e(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}

	//Read
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ReadJaegerHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = r(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}
}

func TestRedisHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var e = MakeExecRedisHealthCheckEndpoint(mockComponent)
	var r = MakeReadRedisHealthCheckEndpoint(mockComponent)

	//Exec
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ExecRedisHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = e(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}

	//Read
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ReadRedisHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = r(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}
}

func TestSentryHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var e = MakeExecSentryHealthCheckEndpoint(mockComponent)
	var r = MakeReadSentryHealthCheckEndpoint(mockComponent)

	//Exec
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ExecSentryHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = e(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}

	//Read
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ReadSentryHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = r(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}
}

func TestKeycloakHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var e = MakeExecKeycloakHealthCheckEndpoint(mockComponent)
	var r = MakeReadKeycloakHealthCheckEndpoint(mockComponent)

	//Exec
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ExecKeycloakHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = e(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}

	//Read
	{
		var j = json.RawMessage(`{"Name":"Test","Status":"OK"}`)
		mockComponent.EXPECT().ReadKeycloakHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = r(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Name":"Test","Status":"OK"}`, string(json))
	}
}

func TestAllHealthChecksEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var e = MakeAllHealthChecksEndpoint(mockComponent)

	{
		var j = json.RawMessage(`{"Redis":[{"Name":"Test","Status":"OK"}]}`)
		mockComponent.EXPECT().AllHealthChecks(context.Background()).Return(j).Times(1)
		var reports, err = e(context.Background(), nil)
		assert.Nil(t, err)
		var json, _ = json.Marshal(&reports)
		assert.Equal(t, `{"Redis":[{"Name":"Test","Status":"OK"}]}`, string(json))
	}
}
