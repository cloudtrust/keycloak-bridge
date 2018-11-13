package middleware

import (
	"bytes"
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/flaki/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware/mock"
	"github.com/golang/mock/gomock"
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestHTTPCorrelationIDMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockFlakiClient = mock.NewFlakiClient(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
		flakiID       = strconv.FormatUint(rand.Uint64(), 10)
		corrID        = strconv.FormatUint(rand.Uint64(), 10)
	)

	// With header 'X-Correlation-ID'
	{
		var mockHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var id = req.Context().Value("correlation_id").(string)
			assert.Equal(t, corrID, id)
		})

		var m = MakeHTTPCorrelationIDMW(mockFlakiClient, mockTracer, mockLogger, componentName, componentID)(mockHandler)

		// HTTP request.
		var req = httptest.NewRequest("GET", "http://cloudtrust.io/getusers", bytes.NewReader([]byte{}))
		req.Header.Add("X-Correlation-ID", corrID)
		var w = httptest.NewRecorder()

		m.ServeHTTP(w, req)
	}

	// Without header 'X-Correlation-ID', so there is a call to Flaki without the tracing.
	{
		var mockHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var id = req.Context().Value("correlation_id").(string)
			assert.Equal(t, flakiID, id)
		})
		var m = MakeHTTPCorrelationIDMW(mockFlakiClient, mockTracer, mockLogger, componentName, componentID)(mockHandler)

		// HTTP request.
		var req = httptest.NewRequest("GET", "http://cloudtrust.io/getusers", bytes.NewReader([]byte{}))
		var w = httptest.NewRecorder()

		mockFlakiClient.EXPECT().NextID(gomock.Any(), gomock.Any()).Return(createFlakiReply(flakiID), nil).Times(1)
		m.ServeHTTP(w, req)
	}
}

func TestGRPCCorrelationIDMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockFlakiClient = mock.NewFlakiClient(mockCtrl)
	var mockGRPCHandler = mock.NewHandler(mockCtrl)

	var (
		componentName = "keycloak-bridge"
		componentID   = strconv.FormatUint(rand.Uint64(), 10)
		flakiID       = strconv.FormatUint(rand.Uint64(), 10)
		corrID        = strconv.FormatUint(rand.Uint64(), 10)
	)

	var m = MakeGRPCCorrelationIDMW(mockFlakiClient, mockTracer, mockLogger, componentName, componentID)(mockGRPCHandler)

	// With correlation ID in metadata.
	var correlationIDMD = metadata.New(map[string]string{"correlation_id": corrID})
	var ctx = metadata.NewIncomingContext(context.Background(), correlationIDMD)

	mockGRPCHandler.EXPECT().ServeGRPC(gomock.Any(), nil).Return(context.Background(), nil, nil).Times(1)
	m.ServeGRPC(ctx, nil)

	// Without correlation ID in metadata.
	mockGRPCHandler.EXPECT().ServeGRPC(gomock.Any(), nil).Return(context.Background(), nil, nil).Times(1)
	mockFlakiClient.EXPECT().NextID(gomock.Any(), gomock.Any()).Return(createFlakiReply(flakiID), nil).Times(1)
	m.ServeGRPC(context.Background(), nil)
}

func createFlakiReply(id string) *fb.FlakiReply {
	var b = flatbuffers.NewBuilder(0)

	var idStr = b.CreateString(id)
	fb.FlakiReplyStart(b)
	fb.FlakiReplyAddId(b, idStr)
	b.Finish(fb.FlakiReplyEnd(b))

	return fb.GetRootAsFlakiReply(b.FinishedBytes(), 0)
}
