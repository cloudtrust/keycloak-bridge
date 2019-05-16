package middleware

import (
	"bytes"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestHTTPCorrelationIDMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockIDGenerator = mock.NewIDGenerator(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
		corrID        = strconv.FormatUint(rand.Uint64(), 10)
	)

	// With header 'X-Correlation-ID'
	{
		var mockHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var id = req.Context().Value(cs.CtContextCorrelationID).(string)
			assert.Equal(t, corrID, id)
		})

		var m = MakeHTTPCorrelationIDMW(mockIDGenerator, mockTracer, mockLogger, componentName, componentID)(mockHandler)

		// HTTP request.
		var req = httptest.NewRequest("GET", "http://cloudtrust.io/getusers", bytes.NewReader([]byte{}))
		req.Header.Add("X-Correlation-ID", corrID)
		var w = httptest.NewRecorder()

		m.ServeHTTP(w, req)
	}

	// Without header 'X-Correlation-ID', so there is a call to IDGenerator.
	{
		var mockHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var id = req.Context().Value(cs.CtContextCorrelationID).(string)
			assert.Equal(t, "keycloak_brdige-123456789-12645316163-45641615174715", id)
		})
		var m = MakeHTTPCorrelationIDMW(mockIDGenerator, mockTracer, mockLogger, componentName, componentID)(mockHandler)

		// HTTP request.
		var req = httptest.NewRequest("GET", "http://cloudtrust.io/getusers", bytes.NewReader([]byte{}))
		var w = httptest.NewRecorder()

		mockIDGenerator.EXPECT().NextID().Return("keycloak_brdige-123456789-12645316163-45641615174715").Times(1)
		m.ServeHTTP(w, req)
	}
}
