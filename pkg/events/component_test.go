package events

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/database"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	dBModule *mock.EventsDBModule
	writeDB  *mock.WriteDBModule
	logger   *mock.Logger
}

func createComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		dBModule: mock.NewEventsDBModule(mockCtrl),
		writeDB:  mock.NewWriteDBModule(mockCtrl),
		logger:   mock.NewLogger(mockCtrl),
	}
}

func (m *componentMocks) createComponent() Component {
	return NewComponent(m.dBModule, m.writeDB, m.logger)
}

func executeTest(t *testing.T, tester func(mocks *componentMocks, component Component)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)

	tester(mocks, mocks.createComponent())
}

func TestGetActions(t *testing.T) {
	executeTest(t, func(mocks *componentMocks, component Component) {
		// Execute test
		res, err := component.GetActions(context.Background())

		// Check result
		assert.Nil(t, err)
		assert.Equal(t, len(actions), len(res))
	})
}

func TestGetEvents(t *testing.T) {
	executeTest(t, func(mocks *componentMocks, component Component) {
		params := make(map[string]string)
		var emptyAudits [0]api.AuditRepresentation
		var expected api.AuditEventsRepresentation
		expected.Count = 1
		expected.Events = emptyAudits[:]
		// Prepare test
		mocks.dBModule.EXPECT().GetEventsCount(gomock.Any(), params).Return(expected.Count, nil).Times(1)
		mocks.dBModule.EXPECT().GetEvents(gomock.Any(), params).Return(expected.Events, nil).Times(1)

		// Execute test
		res, err := component.GetEvents(context.Background(), params)

		// Check result
		assert.Nil(t, err)
		assert.Equal(t, expected.Count, res.Count)
		assert.Equal(t, 0, len(res.Events))
	})
}

func TestGetUserEventsWithResult(t *testing.T) {
	executeTest(t, func(mocks *componentMocks, component Component) {
		params := initMap(prmPathRealm, "master", prmPathUserID, "123-456")
		expectedCount := 1
		expectedResult := []api.AuditRepresentation{}

		t.Run("Success", func(t *testing.T) {
			mocks.dBModule.EXPECT().GetEventsCount(gomock.Any(), params).Return(expectedCount, nil).Times(1)
			mocks.dBModule.EXPECT().GetEvents(gomock.Any(), params).Return(expectedResult, nil).Times(1)
			mocks.writeDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

			// Execute test
			res, err := component.GetUserEvents(context.Background(), params)

			assert.Nil(t, err)
			assert.Equal(t, expectedCount, res.Count)
			assert.Equal(t, expectedResult, res.Events)
		})

		t.Run("storing the event in the DB fails", func(t *testing.T) {
			mocks.dBModule.EXPECT().GetEventsCount(gomock.Any(), params).Return(expectedCount, nil).Times(1)
			mocks.dBModule.EXPECT().GetEvents(gomock.Any(), params).Return(expectedResult, nil).Times(1)
			mocks.writeDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
			m := map[string]interface{}{"event_name": "GET_ACTIVITY", database.CtEventRealmName: params[prmPathRealm], database.CtEventUserID: params[prmPathUserID]}
			eventJSON, _ := json.Marshal(m)
			mocks.logger.EXPECT().Error(gomock.Any(), "err", "error", "event", string(eventJSON))
			// Execute test
			res, err := component.GetUserEvents(context.Background(), params)

			assert.Nil(t, err)
			assert.Equal(t, expectedCount, res.Count)
			assert.Equal(t, expectedResult, res.Events)
		})
	})
}

func TestGetUserEventsWithZeroCount(t *testing.T) {
	executeTest(t, func(mocks *componentMocks, component Component) {
		// Prepare test
		params := initMap(prmPathRealm, "master", prmPathUserID, "123-456")
		mocks.dBModule.EXPECT().GetEventsCount(gomock.Any(), params).Return(0, nil).Times(1)
		mocks.dBModule.EXPECT().GetEvents(gomock.Any(), gomock.Any()).Times(0)
		mocks.writeDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

		// Execute test
		res, err := component.GetUserEvents(context.Background(), params)

		// Check result
		assert.Nil(t, err)
		assert.Equal(t, 0, res.Count)
	})
}

func testInvalidRealmUserID(t *testing.T, params map[string]string) {
	executeTest(t, func(mocks *componentMocks, component Component) {
		// Prepare test
		mocks.dBModule.EXPECT().GetEventsCount(gomock.Any(), gomock.Any()).Times(0)
		mocks.dBModule.EXPECT().GetEvents(gomock.Any(), gomock.Any()).Times(0)
		mocks.writeDB.EXPECT().ReportEvent(gomock.Any(), "GET_ACTIVITY", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		// Execute test
		res, err := component.GetUserEvents(context.Background(), params)

		// Check result
		assert.NotNil(t, err)
		assert.Equal(t, 0, res.Count)
	})
}

func TestGetUserEventsEmptyUserID(t *testing.T) {
	testInvalidRealmUserID(t, initMap(prmPathRealm, "master", prmPathUserID, ""))
}

func TestGetUserEventsMissingUserID(t *testing.T) {
	testInvalidRealmUserID(t, initMap(prmPathRealm, "master"))
}

func TestGetUserEventsEmptyRealm(t *testing.T) {
	testInvalidRealmUserID(t, initMap(prmPathRealm, "", prmPathUserID, "123-456-789"))
}

func TestGetUserEventsMissingRealm(t *testing.T) {
	testInvalidRealmUserID(t, initMap(prmPathUserID, "123-456-789"))
}

func initMap(params ...string) map[string]string {
	res := make(map[string]string)

	noTuples := len(params)
	for i := 0; i+1 < noTuples; i = i + 2 {
		res[params[i]] = params[i+1]
	}

	return res
}

func TestGetEventsSummary(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	// Prepare test
	mocks.dBModule.EXPECT().GetEventsSummary(gomock.Any()).Return(api.EventSummaryRepresentation{
		Origins: []string{
			"origin-1",
		},
	}, nil).Times(1)

	// Execute test
	res, err := component.GetEventsSummary(context.Background())

	// Check result
	assert.Nil(t, err)
	assert.Equal(t, 1, len(res.Origins))
}
