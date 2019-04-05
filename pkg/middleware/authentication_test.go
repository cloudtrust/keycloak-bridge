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

func TestHTTPOIDCTokenValidationMW(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiJhODg4NTIyNS1kODU5LTRjNDUtODYwZS05YTNjZGYxYjUzZDAiLCJleHAiOjE1NTIyOTQ1NDgsIm5iZiI6MCwiaWF0IjoxNTUyMjkzOTQ4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwic3ViIjoiNzM5M2FiMWEtNWIwNC00M2Y1LTgwNDktOGE5NDkyMzJlZDBhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYWRtaW4tY2xpIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiYzdkNTllNTktNTNiYi00Y2IzLThhMTYtZTI3OGI0NWE2OTI5IiwiYWNyIjoiMSIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4ifQ.WOgsWPdKt1f8gp7AkqCGzoBgkeYgN9YyYlAHILuBG5o9ZN0Ae4Bpymci0tkDWEsQk532mfSyP6-0uLwcNOHf_kPpqjjJ4k6Cnz4p1s6bWTOjPP1cTGcs0bUCiYJI0ZRz3oPjz8RSBH2bDe7Dq7p1STZwLLtX-0uc3t5le0EGSobSoVfOdVBU-TFda4R0xKK7cCsJzw-pOGHFOuoFUhEiruo6Ibo_-iNLxht5rUh8KMoeUkGF3dn1rshT55tq9WY7q6fygUxZS8C_4NvVTfaPo76JO2rUQ5FAhOJRlBACEwALrdpw7Tr0Ox8fjZLIrLeIswMNbGNmpTxEH3LK-ull8g"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, mockLogger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/test", bytes.NewReader([]byte{}))

	// Missing authorization token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorisation Error", "Missing Authorization header").Return(nil).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	req.Header.Set("Authorization", "Non bearer format")

	// Missing bearer token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorisation Error", "Missing bearer token").Return(nil).Times(1)
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

	// Invalid authorization token.
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorisation Error", gomock.Any()).Return(nil).Times(1)
		mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(fmt.Errorf("Invalid token")).Times(1)
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

	// Invalid token format
	{
		var w = httptest.NewRecorder()
		mockLogger.EXPECT().Log("Authorisation Error", gomock.Any()).Return(nil).Times(1)
		req = httptest.NewRequest("POST", "http://cloudtrust.io/management/test", bytes.NewReader([]byte{}))
		req.Header.Set("Authorization", "Bearer 123456ABCDEF")
		m.ServeHTTP(w, req)
		var result = w.Result()
		assert.Equal(t, 403, result.StatusCode)
	}

}

func TestContextHTTPOIDCTokenValidationMW(t *testing.T) {
	var token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJZTVzcXBLdTNwb1g5d1U3YTBhamxnUFlGRHFTTUF5M2l6NEZpelp4d2dnIn0.eyJqdGkiOiI3NTA4ZWE2ZC0wMGQzLTRjM2YtOTk2Yi01ZDNhODZkZWRiOTciLCJleHAiOjE1NTQ0OTI0NTcsIm5iZiI6MCwiaWF0IjoxNTU0NDU2NDU3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwic3ViIjoiNzM5M2FiMWEtNWIwNC00M2Y1LTgwNDktOGE5NDkyMzJlZDBhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYWRtaW4tY2xpIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiMDJiOGZmMWYtMmRmYS00NmNhLThiN2MtNzA2YTQwNDA1NzlkIiwiYWNyIjoiMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZ3JvdXBzIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJncm91cHMiOlsiL3RvZSJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiIsImVtYWlsIjoidmluY2VudC5sb3VwQGVsY2EuY2gifQ.gbAsszn0pr5yGdF9naURY1TlfKcsvPghoHrdJybN-9k0EE9mLfksDSsCrJnLj5o-1OinQ0GSRi1Y-DwHZgpP4RvPtWHr7_3zdidr8aJQuooJ3Vgdx7LcBSlBUl_YSzHL_fO5k0rxIR2tVZeMaFJXOpm_PNuyKeFeu8EbqOQdAMRDkBlLPNXeyBGpBAAXDAbGNL71ROlMcZotqLGipiweQjEMOqyp304qIn9Z-t1FvIvh8XkYIoU2eHgwWl4cjf_uFGzqdzGLSvV_z79dEILaG9P-dgvO4xRy8ciju2ii5kB0pZNWf2VDorFeYRwELHSbWt9ZEwZzaV5b5bv9gHKn4A"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewManagementComponent(mockCtrl)

	var endpoint = management.MakeGetRealmEndpoint(mockComponent)
	var handler = management.MakeManagementHandler(endpoint)
	var m = MakeHTTPOIDCTokenValidationMW(mockKeycloakClient, mockLogger)(handler)

	// HTTP request.
	var req = httptest.NewRequest("POST", "http://cloudtrust.io/management/realms/master", bytes.NewReader([]byte{}))

	req.Header.Set("Authorization", "Bearer "+token)

	var w = httptest.NewRecorder()
	mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(nil).Times(1)
	mockComponent.EXPECT().GetRealm(gomock.Any(), gomock.Any()).DoAndReturn(func (ctx context.Context, realm string) (api.RealmRepresentation, error){
		var accessToken = ctx.Value("access_token").(string)
		var realmCtx = ctx.Value("realm").(string)
		var username = ctx.Value("username").(string)
		var groups = ctx.Value("groups").([]string)

		assert.Equal(t, accessToken, token)
		assert.Equal(t, "master", realmCtx)
		assert.Equal(t, "admin", username)
		assert.Equal(t, []string{"toe"}, groups)

		return api.RealmRepresentation{}, nil
	}).Times(1)

	m.ServeHTTP(w, req)
	var result = w.Result()
	assert.Equal(t, 200, result.StatusCode)

}
