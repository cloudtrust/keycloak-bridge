package management

/*
func TestHTTPManagementHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var managementHandler = MakeManagementHandler(MakeGetRealmEndpoint(mockComponent))

	// HTTP request.
	var httpReq = httptest.NewRequest("GET", "http://localhost:8888/management/realms/master", nil)
	var w = httptest.NewRecorder()

	// Management request (i.e. Get a realm)
	{
		mockComponent.EXPECT().GetRealm(context.Background(), "master").Return(api.RealmRepresentation{}, nil).Times(1)
		managementHandler.ServeHTTP(w, httpReq)
		var res = w.Result()
		var _, err = ioutil.ReadAll(res.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	}
}*/

/*
func TestHTTPErrorHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewMuxComponent(mockCtrl)

	var eventHandler = MakeHTTPEventHandler(MakeEventEndpoint(mockComponent))

	rand.Seed(time.Now().UnixNano())
	var uid = rand.Int63()
	var eventByte = createEventBytes(fb.OperationTypeCREATE, uid, "realm")
	var eventString = base64.StdEncoding.EncodeToString(eventByte)

	// Internal server error.
	{
		// HTTP request.
		var body = strings.NewReader(fmt.Sprintf(`{"type": "Event", "Obj": "%s"}`, eventString))
		var httpReq = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
		var w = httptest.NewRecorder()

		mockComponent.EXPECT().Event(context.Background(), "Event", eventByte).Return(fmt.Errorf("fail")).Times(1)
		eventHandler.ServeHTTP(w, httpReq)
		var res = w.Result()
		var data, err = ioutil.ReadAll(res.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.Equal(t, "application/json; charset=utf-8", res.Header.Get("Content-Type"))
		assert.NotZero(t, string(data))
	}

	// Bad request.
	{
		// Bad HTTP request.
		var body = strings.NewReader(fmt.Sprintf(`{"type": "Unknown", "Obj": "%s"}`, eventString))
		var httpReq = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
		var w = httptest.NewRecorder()

		eventHandler.ServeHTTP(w, httpReq)
		var res = w.Result()
		var data, err = ioutil.ReadAll(res.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Equal(t, "application/json; charset=utf-8", res.Header.Get("Content-Type"))
		assert.NotZero(t, string(data))
	}
}

func TestDecodeValidRequest(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	var uid = rand.Int63()
	var eventByte = createAdminEventBytes(fb.OperationTypeACTION, uid)
	var eventString = base64.StdEncoding.EncodeToString(eventByte)
	var body = strings.NewReader(fmt.Sprintf(`{"type": "AdminEvent", "Obj": "%s"}`, eventString))
	var req = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)

	var res, err = decodeHTTPRequest(context.Background(), req)
	assert.Nil(t, err)

	var r, ok = res.(Request)
	assert.True(t, ok)
	assert.Equal(t, "AdminEvent", r.Type)
	assert.Equal(t, eventByte, r.Object)
}


func TestDecodeInvalidRequest(t *testing.T) {
	var body = strings.NewReader(`{"type": "Event", "Obj": "test"}`)
	var req = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)

	var res, err = decodeHTTPRequest(context.Background(), req)
	assert.NotNil(t, err)
	assert.IsType(t, ErrInvalidArgument{}, errors.Cause(err))
	assert.Nil(t, res)
}

func TestFetchHTTPCorrelationID(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewMuxComponent(mockCtrl)

	var eventHandler = MakeHTTPEventHandler(MakeEventEndpoint(mockComponent))

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var uid = rand.Int63()
	var eventByte = createEventBytes(fb.OperationTypeCREATE, uid, "realm")
	var eventString = base64.StdEncoding.EncodeToString(eventByte)

	// HTTP request.
	var body = strings.NewReader(fmt.Sprintf(`{"type": "Event", "Obj": "%s"}`, eventString))
	var httpReq = httptest.NewRequest("POST", "http://localhost:8888/event/id", body)
	httpReq.Header.Add("X-Correlation-ID", corrID)
	var w = httptest.NewRecorder()

	mockComponent.EXPECT().Event(ctx, "Event", eventByte).Return(nil).Times(1)
	eventHandler.ServeHTTP(w, httpReq)
}
*/
