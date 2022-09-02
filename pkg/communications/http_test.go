package communications

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHTTPCommunicationsHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var realm = "example"

	var communicationsHandler = MakeCommunicationsHandler(keycloakb.ToGoKitEndpoint(MakeSendEmailEndpoint(mockComponent)), mockLogger)
	var communicationsHandler2 = MakeCommunicationsHandler(keycloakb.ToGoKitEndpoint(MakeSendSMSEndpoint(mockComponent)), mockLogger)

	r := mux.NewRouter()
	r.Handle("/communications/realms/{realm}/send-mail", communicationsHandler)
	r.Handle("/communications/realms/{realm}/send-sms", communicationsHandler2)

	ts := httptest.NewServer(r)
	defer ts.Close()

	{

		mockComponent.EXPECT().SendEmail(gomock.Any(), realm, emailForTest).Return(nil).Times(1)

		emailJSON, _ := json.Marshal(emailForTest)
		var body = strings.NewReader(string(emailJSON))
		res, err := http.Post(ts.URL+"/communications/realms/example/send-mail", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusNoContent, res.StatusCode)
	}

	{

		mockComponent.EXPECT().SendSMS(gomock.Any(), realm, smsForTest).Return(nil).Times(1)

		smsJSON, _ := json.Marshal(smsForTest)
		var body = strings.NewReader(string(smsJSON))
		res, err := http.Post(ts.URL+"/communications/realms/example/send-sms", "application/json", body)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	}
}
