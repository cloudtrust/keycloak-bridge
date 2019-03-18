package middleware

//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/middleware KeycloakClient

import (
	"bytes"
	"testing"
	"net/http"
	"net/http/httptest"
	"fmt"
	"context"

	"github.com/cloudtrust/keycloak-bridge/pkg/middleware/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/cloudtrust/keycloak-bridge/pkg/management"
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
	req.Header.Set("Authorization", "Bearer "+token)

	var w = httptest.NewRecorder()


	// Valid authorization token.
	mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(nil).Times(1)
	m.ServeHTTP(w, req)
	var result = w.Result()
	assert.Equal(t, 200, result.StatusCode)

	// Valid authorization token.
	mockKeycloakClient.EXPECT().VerifyToken("master", token).Return(fmt.Errorf("Invalid token")).Times(1)
	m.ServeHTTP(w, req)
	result = w.Result()
	assert.Equal(t, 403, result.StatusCode)

	// Invalid token format
	req = httptest.NewRequest("POST", "http://cloudtrust.io/management/test", bytes.NewReader([]byte{}))
	req.Header.Set("Authorization", "Bearer 123456ABCDEF")
	m.ServeHTTP(w, req)
	result = w.Result()
	assert.Equal(t, 403, result.StatusCode)

}



func TestEndpointTokenForRealmMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeEndpointTokenForRealmMW(mockLogger)(management.MakeTestEndpoint())


	// Mismatch between authorised realm and requested one
	// Context with realm coming from HTTP OIDC MW.
	var ctx = context.WithValue(context.Background(), "realm", "client")
	
	var req = map[string]string {"realm": "master"}
	_, err := m(ctx, req)

	assert.NotNil(t, err)

	// Match between authorised realm and requested one
	// Context with realm coming from HTTP OIDC MW.
	ctx = context.WithValue(context.Background(), "realm", "master")
	
	req = map[string]string {"realm": "master"}
	_, err = m(ctx, req)

	assert.Nil(t, err)

	// Missing requested realm information
	// Context with realm coming from HTTP OIDC MW.
	ctx = context.WithValue(context.Background(), "realm", "master")
	
	req = map[string]string {}
	_, err = m(ctx, req)

	assert.NotNil(t, err)

	// Missing authorized realm information
	// Context with realm coming from HTTP OIDC MW.
	ctx = context.Background()
	
	req = map[string]string {"realm": "master"}
	_, err = m(ctx, req)

	assert.NotNil(t, err)
}
