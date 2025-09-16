package components

import (
	"testing"
)

// import (
// 	"testing"
// )

func TestHTTPComponentpHandler(t *testing.T) {
	// var mockCtrl = gomock.NewController(t)
	// defer mockCtrl.Finish()
	// var mockComponent = mock.NewComponent(mockCtrl)
	// var mockLogger = log.NewNopLogger()

	// var realm = "example"
	// var apiComp = testApiComp()

	// var compHandler = MakeComponentHandler(keycloakb.ToGoKitEndpoint(MakeCreateComponentEndpoint(mockComponent)), mockLogger)
	// var compHandler2 = MakeComponentHandler(keycloakb.ToGoKitEndpoint(MakeDeleteComponentEndpoint(mockComponent)), mockLogger)

	// r := mux.NewRouter()
	// r.Handle("/components/realms/{realm}/components", compHandler)
	// r.Handle("/components/realms/{realm}/components/{provider}", compHandler2)

	// ts := httptest.NewServer(r)
	// defer ts.Close()

	// {
	// 	mockComponent.EXPECT().CreateComponent(gomock.Any(), realm, apiComp).Return(nil).Times(1)

	// 	compsJSON, _ := json.Marshal(apiComp)
	// 	var body = strings.NewReader(string(compsJSON))
	// 	res, err := http.Post(ts.URL+"/components/realms/"+realm+"/components", "application/json", body)

	// 	assert.Nil(t, err)
	// 	assert.Equal(t, http.StatusOK, res.StatusCode)
	// }

	// {
	// 	mockComponent.EXPECT().GetComponent(gomock.Any(), realm, compID).Return(apiComp, nil).Times(1)

	// 	res, err := http.Get(ts.URL + "/components/realms/" + realm + "/components/" + compID)

	// 	assert.Nil(t, err)
	// 	assert.Equal(t, http.StatusOK, res.StatusCode)
	// }

}
