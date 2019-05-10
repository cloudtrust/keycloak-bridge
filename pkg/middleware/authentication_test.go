package middleware

//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/middleware KeycloakClient
//go:generate mockgen -destination=./mock/management_component.go -package=mock -mock_names=ManagementComponent=ManagementComponent github.com/cloudtrust/keycloak-bridge/pkg/management ManagementComponent

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestHTTPBasicAuthenticationMW(t *testing.T) {
	var token = "dXNlcm5hbWU6cGFzc3dvcmQ="

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeHTTPBasicAuthenticationMW("password", mockLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/event/receiver", bytes.NewReader([]byte{}))

	// Missing authorization token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", "Missing Authorization header").Return(nil).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	req.Header.Set("Authorization", "Non basic format")

	// Missing basic token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", "Missing basic token").Return(nil).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	req.Header.Set("Authorization", "Basic "+token)

	// Valid authorization token.
	{
		var w = httptest.NewRecorder()
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 200, result.StatusCode)
	}

	req.Header.Set("Authorization", "basic "+token)

	// Valid authorization token.
	{
		var w = httptest.NewRecorder()
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 200, result.StatusCode)
	}

	req.Header.Set("Authorization", "basic dXNlcm5hbWU6cGFzc3dvcmQx")

	// Invalid authorization token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", "Invalid password value").Return(nil).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	req.Header.Set("Authorization", "basic "+token)

	// Invalid token format
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", gomock.Any()).Return(nil).Times(1)
		req = httptest.NewRequest("POST", "http://cloudtrust.io/management/test", bytes.NewReader([]byte{}))
		req.Header.Set("Authorization", "Basic 123456ABCDEF")
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	// Invalid token format
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", gomock.Any()).Return(nil).Times(1)
		req = httptest.NewRequest("POST", "http://cloudtrust.io/management/test", bytes.NewReader([]byte{}))
		req.Header.Set("Authorization", "Basic dXNlcm5hbWU=")
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

}

func TestHTTPOIDCTokenValidationMW(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiI4MDY4MjZkNy0xZjM4LTQxZjgtYTk5Ni1iYTYzYWI0YTY3MGIiLCJleHAiOjE1NTY2NjY3NzAsIm5iZiI6MCwiaWF0IjoxNTU2NjMwNzcwLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdC1yZWFsbSIsInN1YiI6IjczOTNhYjFhLTViMDQtNDNmNS04MDQ5LThhOTQ5MjMyZWQwYSIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFkbWluLWNsaSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjFlMmI1Mzk5LTgyNDItNDA1OS05Y2M1LWE5MzI0NDVlY2JkMSIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsidGVzdC1yZWFsbSI6eyJyb2xlcyI6WyJ2aWV3LXJlYWxtIiwidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsImNyZWF0ZS1jbGllbnQiLCJtYW5hZ2UtdXNlcnMiLCJxdWVyeS1yZWFsbXMiLCJ2aWV3LWF1dGhvcml6YXRpb24iLCJxdWVyeS1jbGllbnRzIiwicXVlcnktdXNlcnMiLCJtYW5hZ2UtZXZlbnRzIiwibWFuYWdlLXJlYWxtIiwidmlldy1ldmVudHMiLCJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwibWFuYWdlLWF1dGhvcml6YXRpb24iLCJtYW5hZ2UtY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZ3JvdXBzIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJncm91cHMiOlsiL3RvZV9hZG1pbmlzdHJhdG9yIl0sInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIiwiZW1haWwiOiJ0b3RvQHRvdG8uY29tIn0.QXUTPciZYYv8k688D27sOz5thyQH1OWwp-rqTnCQYoAbqXPVgSZxLIepk8JvS9drBl7jOH-M_w2tXMOjV-7kY7p57_9VyWaI42VgBVmJVXSWwMwPtWAwnpKqMh1wrrm_zYJRmZ43o1r6Rp_kELnfgwocFSLc3DTDVEoMuYE45kJg9JwPc2K7DYi6Om5qOm9ez-x8GpyGVy3xJiOa-Qr9oJpKCx02sRVEBIc0AE0pfpxfbBhJU06L4uVnwQ1JxquLKLU77bjPEkAKOnTeG-6D9OtH_K42KujZyhj7FytXAXv9CmISi9aIe7BVANFSu7TyOBjelZHVpI5dOKRc-E2L9w"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, "test-realm", mockLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/test", bytes.NewReader([]byte{}))

	// Missing authorization token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", "Missing Authorization header").Return(nil).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	req.Header.Set("Authorization", "Non bearer format")

	// Missing bearer token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", "Missing bearer token").Return(nil).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	// Valid authorization token.
	{
		var w = httptest.NewRecorder()
		mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(nil).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 200, result.StatusCode)
	}

	req.Header.Set("Authorization", "bearer "+token)

	// Invalid authorization token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", gomock.Any()).Return(nil).Times(1)
		mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(fmt.Errorf("Invalid token")).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	// Invalid token format
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorization Error", gomock.Any()).Return(nil).Times(1)
		req = httptest.NewRequest("POST", "http://cloudtrust.io/management/test", bytes.NewReader([]byte{}))
		req.Header.Set("Authorization", "Bearer 123456ABCDEF")
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

}

func TestContextHTTPOIDCTokenMissingAudience(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiJhODg4NTIyNS1kODU5LTRjNDUtODYwZS05YTNjZGYxYjUzZDAiLCJleHAiOjE1NTIyOTQ1NDgsIm5iZiI6MCwiaWF0IjoxNTUyMjkzOTQ4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwic3ViIjoiNzM5M2FiMWEtNWIwNC00M2Y1LTgwNDktOGE5NDkyMzJlZDBhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYWRtaW4tY2xpIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiYzdkNTllNTktNTNiYi00Y2IzLThhMTYtZTI3OGI0NWE2OTI5IiwiYWNyIjoiMSIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4ifQ.WOgsWPdKt1f8gp7AkqCGzoBgkeYgN9YyYlAHILuBG5o9ZN0Ae4Bpymci0tkDWEsQk532mfSyP6-0uLwcNOHf_kPpqjjJ4k6Cnz4p1s6bWTOjPP1cTGcs0bUCiYJI0ZRz3oPjz8RSBH2bDe7Dq7p1STZwLLtX-0uc3t5le0EGSobSoVfOdVBU-TFda4R0xKK7cCsJzw-pOGHFOuoFUhEiruo6Ibo_-iNLxht5rUh8KMoeUkGF3dn1rshT55tq9WY7q6fygUxZS8C_4NvVTfaPo76JO2rUQ5FAhOJRlBACEwALrdpw7Tr0Ox8fjZLIrLeIswMNbGNmpTxEH3LK-ull8g"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)
	mockLogger.EXPECT().Log(gomock.Any()).AnyTimes()
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var endpoint = management.MakeGetRealmEndpoint(mockComponent)
	var handler = management.MakeManagementHandler(endpoint, mockLogger)
	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, "audience", mockLogger)(handler)

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/realms/master", bytes.NewReader([]byte{}))

	req.Header.Set("Authorization", "Bearer "+token)

	var w = httptest.NewRecorder()
	mockLogger.EXPECT().Log(gomock.Any()).AnyTimes()

	m.ServeHTTP(w, req)
	var result = w.Result()
	assert.Equal(t, 403, result.StatusCode)
}

func TestContextHTTPOIDCTokenAudienceStringArrayValidationMW(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiIwYzYyY2JjMS1hOThlLTQ1NDAtOTM1ZC00NGUwM2M2ZWZkMTAiLCJleHAiOjE1NTY2NjY1MTMsIm5iZiI6MCwiaWF0IjoxNTU2NjMwNTEzLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjpbInJwby1yZWFsbSIsInRlc3QtcmVhbG0iXSwic3ViIjoiNzM5M2FiMWEtNWIwNC00M2Y1LTgwNDktOGE5NDkyMzJlZDBhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYWRtaW4tY2xpIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiYmEwZjkyNWItZTdhNC00MTBkLWJjY2EtZjU4NzExMWNhOTZlIiwiYWNyIjoiMSIsInJlc291cmNlX2FjY2VzcyI6eyJycG8tcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sInRlc3QtcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGdyb3VwcyBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ3JvdXBzIjpbIi90b2VfYWRtaW5pc3RyYXRvciJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiIsImVtYWlsIjoidG90b0B0b3RvLmNvbSJ9.Q62PHuOme8Debm8uhdtvEdMmd5ZX7xrdPfgcgR9MpsInQzykrFZdjUufFQQ1wJw35eaHDdLABXe-IxHPJvqzRS_FrQ54sLGDZz9w6T8umywuSG4VP2UKtJkV7-c1Jswyeq2cbfchteyAsnByXipjXKFYLrWGz5VrtxZKgLbF3lqtLmJzo9RzlEuxbynX0L63kLJism0CWOSxfQuGknMEy9RYp7MmivlHUvisjBMY1lWVyK-cNJUZOyFcANh3PclVrPdZW1QFbynHCnFOfO38vjW7f7Vy2DeGC23YbBG2ZZFRAD7rgM_VfCqjH10w-iGa6G7avOwSD7tGXQCMWLp7Zw"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var endpoint = management.MakeGetRealmEndpoint(mockComponent)
	var handler = management.MakeManagementHandler(endpoint, mockLogger)
	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, "rpo-realm", mockLogger)(handler)

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/realms/master", bytes.NewReader([]byte{}))

	req.Header.Set("Authorization", "Bearer "+token)

	var w = httptest.NewRecorder()
	mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(nil).Times(1)
	mockComponent.EXPECT().GetRealm(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, realm string) (api.RealmRepresentation, error) {
		var accessToken = ctx.Value("access_token").(string)
		var realmCtx = ctx.Value("realm").(string)
		var username = ctx.Value("username").(string)
		var groups = ctx.Value("groups").([]string)

		assert.Equal(t, accessToken, token)
		assert.Equal(t, "master", realmCtx)
		assert.Equal(t, "admin", username)
		assert.Equal(t, []string{"toe_administrator"}, groups)

		return api.RealmRepresentation{}, nil
	}).Times(1)

	m.ServeHTTP(w, req)
	var result = w.Result()
	assert.Equal(t, 200, result.StatusCode)
}

func TestContextHTTPOIDCTokenInvalidAudienceStringArrayMW(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiIwYzYyY2JjMS1hOThlLTQ1NDAtOTM1ZC00NGUwM2M2ZWZkMTAiLCJleHAiOjE1NTY2NjY1MTMsIm5iZiI6MCwiaWF0IjoxNTU2NjMwNTEzLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjpbInJwby1yZWFsbSIsInRlc3QtcmVhbG0iXSwic3ViIjoiNzM5M2FiMWEtNWIwNC00M2Y1LTgwNDktOGE5NDkyMzJlZDBhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYWRtaW4tY2xpIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiYmEwZjkyNWItZTdhNC00MTBkLWJjY2EtZjU4NzExMWNhOTZlIiwiYWNyIjoiMSIsInJlc291cmNlX2FjY2VzcyI6eyJycG8tcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sInRlc3QtcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGdyb3VwcyBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZ3JvdXBzIjpbIi90b2VfYWRtaW5pc3RyYXRvciJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiIsImVtYWlsIjoidG90b0B0b3RvLmNvbSJ9.Q62PHuOme8Debm8uhdtvEdMmd5ZX7xrdPfgcgR9MpsInQzykrFZdjUufFQQ1wJw35eaHDdLABXe-IxHPJvqzRS_FrQ54sLGDZz9w6T8umywuSG4VP2UKtJkV7-c1Jswyeq2cbfchteyAsnByXipjXKFYLrWGz5VrtxZKgLbF3lqtLmJzo9RzlEuxbynX0L63kLJism0CWOSxfQuGknMEy9RYp7MmivlHUvisjBMY1lWVyK-cNJUZOyFcANh3PclVrPdZW1QFbynHCnFOfO38vjW7f7Vy2DeGC23YbBG2ZZFRAD7rgM_VfCqjH10w-iGa6G7avOwSD7tGXQCMWLp7Zw"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var endpoint = management.MakeGetRealmEndpoint(mockComponent)
	var handler = management.MakeManagementHandler(endpoint, mockLogger)
	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, "backoffice", mockLogger)(handler)

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/realms/master", bytes.NewReader([]byte{}))

	req.Header.Set("Authorization", "Bearer "+token)

	var w = httptest.NewRecorder()
	mockLogger.EXPECT().Log(gomock.Any()).AnyTimes()

	m.ServeHTTP(w, req)
	var result = w.Result()
	assert.Equal(t, 403, result.StatusCode)
}

func TestContextHTTPOIDCTokenAudienceStringValidationMW(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiI4MDY4MjZkNy0xZjM4LTQxZjgtYTk5Ni1iYTYzYWI0YTY3MGIiLCJleHAiOjE1NTY2NjY3NzAsIm5iZiI6MCwiaWF0IjoxNTU2NjMwNzcwLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdC1yZWFsbSIsInN1YiI6IjczOTNhYjFhLTViMDQtNDNmNS04MDQ5LThhOTQ5MjMyZWQwYSIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFkbWluLWNsaSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjFlMmI1Mzk5LTgyNDItNDA1OS05Y2M1LWE5MzI0NDVlY2JkMSIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsidGVzdC1yZWFsbSI6eyJyb2xlcyI6WyJ2aWV3LXJlYWxtIiwidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsImNyZWF0ZS1jbGllbnQiLCJtYW5hZ2UtdXNlcnMiLCJxdWVyeS1yZWFsbXMiLCJ2aWV3LWF1dGhvcml6YXRpb24iLCJxdWVyeS1jbGllbnRzIiwicXVlcnktdXNlcnMiLCJtYW5hZ2UtZXZlbnRzIiwibWFuYWdlLXJlYWxtIiwidmlldy1ldmVudHMiLCJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwibWFuYWdlLWF1dGhvcml6YXRpb24iLCJtYW5hZ2UtY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZ3JvdXBzIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJncm91cHMiOlsiL3RvZV9hZG1pbmlzdHJhdG9yIl0sInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIiwiZW1haWwiOiJ0b3RvQHRvdG8uY29tIn0.QXUTPciZYYv8k688D27sOz5thyQH1OWwp-rqTnCQYoAbqXPVgSZxLIepk8JvS9drBl7jOH-M_w2tXMOjV-7kY7p57_9VyWaI42VgBVmJVXSWwMwPtWAwnpKqMh1wrrm_zYJRmZ43o1r6Rp_kELnfgwocFSLc3DTDVEoMuYE45kJg9JwPc2K7DYi6Om5qOm9ez-x8GpyGVy3xJiOa-Qr9oJpKCx02sRVEBIc0AE0pfpxfbBhJU06L4uVnwQ1JxquLKLU77bjPEkAKOnTeG-6D9OtH_K42KujZyhj7FytXAXv9CmISi9aIe7BVANFSu7TyOBjelZHVpI5dOKRc-E2L9w"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var endpoint = management.MakeGetRealmEndpoint(mockComponent)
	var handler = management.MakeManagementHandler(endpoint, mockLogger)
	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, "test-realm", mockLogger)(handler)

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/realms/master", bytes.NewReader([]byte{}))

	req.Header.Set("Authorization", "Bearer "+token)

	var w = httptest.NewRecorder()
	mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(nil).Times(1)
	mockComponent.EXPECT().GetRealm(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, realm string) (api.RealmRepresentation, error) {
		var accessToken = ctx.Value("access_token").(string)
		var realmCtx = ctx.Value("realm").(string)
		var username = ctx.Value("username").(string)
		var groups = ctx.Value("groups").([]string)

		assert.Equal(t, accessToken, token)
		assert.Equal(t, "master", realmCtx)
		assert.Equal(t, "admin", username)
		assert.Equal(t, []string{"toe_administrator"}, groups)

		return api.RealmRepresentation{}, nil
	}).Times(1)

	m.ServeHTTP(w, req)
	var result = w.Result()
	assert.Equal(t, 200, result.StatusCode)
}

func TestContextHTTPOIDCTokenInvalidAudienceStringMW(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiI4MDY4MjZkNy0xZjM4LTQxZjgtYTk5Ni1iYTYzYWI0YTY3MGIiLCJleHAiOjE1NTY2NjY3NzAsIm5iZiI6MCwiaWF0IjoxNTU2NjMwNzcwLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdC1yZWFsbSIsInN1YiI6IjczOTNhYjFhLTViMDQtNDNmNS04MDQ5LThhOTQ5MjMyZWQwYSIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFkbWluLWNsaSIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjFlMmI1Mzk5LTgyNDItNDA1OS05Y2M1LWE5MzI0NDVlY2JkMSIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsidGVzdC1yZWFsbSI6eyJyb2xlcyI6WyJ2aWV3LXJlYWxtIiwidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsImNyZWF0ZS1jbGllbnQiLCJtYW5hZ2UtdXNlcnMiLCJxdWVyeS1yZWFsbXMiLCJ2aWV3LWF1dGhvcml6YXRpb24iLCJxdWVyeS1jbGllbnRzIiwicXVlcnktdXNlcnMiLCJtYW5hZ2UtZXZlbnRzIiwibWFuYWdlLXJlYWxtIiwidmlldy1ldmVudHMiLCJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwibWFuYWdlLWF1dGhvcml6YXRpb24iLCJtYW5hZ2UtY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZ3JvdXBzIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJncm91cHMiOlsiL3RvZV9hZG1pbmlzdHJhdG9yIl0sInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIiwiZW1haWwiOiJ0b3RvQHRvdG8uY29tIn0.QXUTPciZYYv8k688D27sOz5thyQH1OWwp-rqTnCQYoAbqXPVgSZxLIepk8JvS9drBl7jOH-M_w2tXMOjV-7kY7p57_9VyWaI42VgBVmJVXSWwMwPtWAwnpKqMh1wrrm_zYJRmZ43o1r6Rp_kELnfgwocFSLc3DTDVEoMuYE45kJg9JwPc2K7DYi6Om5qOm9ez-x8GpyGVy3xJiOa-Qr9oJpKCx02sRVEBIc0AE0pfpxfbBhJU06L4uVnwQ1JxquLKLU77bjPEkAKOnTeG-6D9OtH_K42KujZyhj7FytXAXv9CmISi9aIe7BVANFSu7TyOBjelZHVpI5dOKRc-E2L9w"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var endpoint = management.MakeGetRealmEndpoint(mockComponent)
	var handler = management.MakeManagementHandler(endpoint, mockLogger)
	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, "backoffice", mockLogger)(handler)

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/realms/master", bytes.NewReader([]byte{}))

	req.Header.Set("Authorization", "Bearer "+token)

	var w = httptest.NewRecorder()
	mockLogger.EXPECT().Log(gomock.Any()).AnyTimes()

	m.ServeHTTP(w, req)
	var result = w.Result()
	assert.Equal(t, 403, result.StatusCode)
}
