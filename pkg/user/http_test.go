package user

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
)

func TestHTTPGetUsersHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var getUsersHandler = MakeHTTPGetUsersHandler(MakeGetUsersEndpoint(mockComponent))

	var realm = "master"
	var req = fbUsersRequest(realm)
	var names = []string{"john", "jane", "doe"}
	var reply = fbUsersResponse(names)

	// Flatbuffer request.
	var b = flatbuffers.NewBuilder(0)
	var brealm = b.CreateString(realm)
	fb.GetUsersRequestStart(b)
	fb.GetUsersRequestAddRealm(b, brealm)
	b.Finish(fb.GetUsersRequestEnd(b))

	// HTTP request.
	var httpReq = httptest.NewRequest("POST", "http://cloudtrust.io/getusers", bytes.NewReader(b.FinishedBytes()))
	var w = httptest.NewRecorder()

	// GetUsers.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(reply, nil).Times(1)
	getUsersHandler.ServeHTTP(w, httpReq)
	var res = w.Result()
	var body, err = ioutil.ReadAll(res.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "application/octet-stream", res.Header.Get("Content-Type"))
	// Decode and check reply.
	var r = fb.GetRootAsGetUsersResponse(body, 0)
	for i := 0; i < r.NamesLength(); i++ {
		assert.Contains(t, names, string(r.Names(i)))
	}
}
func TestHTTPErrorHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var getUsersHandler = MakeHTTPGetUsersHandler(MakeGetUsersEndpoint(mockComponent))

	var realm = "master"
	var req = fbUsersRequest(realm)

	// Flatbuffer request.
	var b = flatbuffers.NewBuilder(0)
	var brealm = b.CreateString(realm)
	fb.GetUsersRequestStart(b)
	fb.GetUsersRequestAddRealm(b, brealm)
	b.Finish(fb.GetUsersRequestEnd(b))

	// HTTP request.
	var httpReq = httptest.NewRequest("POST", "http://cloudtrust.io/getusers", bytes.NewReader(b.FinishedBytes()))
	var w = httptest.NewRecorder()

	// GetUsers.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(nil, fmt.Errorf("fail")).Times(1)
	getUsersHandler.ServeHTTP(w, httpReq)
	var res = w.Result()
	var body, err = ioutil.ReadAll(res.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	assert.Equal(t, "application/octet-stream", res.Header.Get("Content-Type"))
	assert.Equal(t, "fail", string(body))
}
func TestFetchHTTPCorrelationID(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var getUsersHandler = MakeHTTPGetUsersHandler(MakeGetUsersEndpoint(mockComponent))

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var realm = "master"
	var req = fbUsersRequest(realm)
	var names = []string{"john", "jane", "doe"}
	var reply = fbUsersResponse(names)

	// Flatbuffer request.
	var b = flatbuffers.NewBuilder(0)
	var brealm = b.CreateString(realm)
	fb.GetUsersRequestStart(b)
	fb.GetUsersRequestAddRealm(b, brealm)
	b.Finish(fb.GetUsersRequestEnd(b))

	// GetUsers.
	{
		var httpReq = httptest.NewRequest("POST", "http://cloudtrust.io/getusers", bytes.NewReader(b.FinishedBytes()))
		httpReq.Header.Add("X-Correlation-ID", corrID)
		var w = httptest.NewRecorder()
		mockComponent.EXPECT().GetUsers(ctx, req).Return(reply, nil).Times(1)
		getUsersHandler.ServeHTTP(w, httpReq)
	}

	// GetUsers without correlation ID.
	{
		var httpReq = httptest.NewRequest("POST", "http://cloudtrust.io/getusers", bytes.NewReader(b.FinishedBytes()))
		var w = httptest.NewRecorder()
		mockComponent.EXPECT().GetUsers(context.Background(), req).Return(reply, nil).Times(1)
		getUsersHandler.ServeHTTP(w, httpReq)
	}
}
