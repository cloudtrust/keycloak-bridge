package communications

import (
	"context"
	"fmt"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	api "github.com/cloudtrust/keycloak-bridge/api/communications"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	keycloakCommunicationsClient *mock.KeycloakCommunicationsClient
	logger                       *mock.Logger
}

var (
	recipientForTest         = "recipient@domain.ch"
	subjectKeyForTest        = "expiryreminder.subject"
	subjectParametersForTest = []string{"my-value"}
	templateForTest          = "expiry-reminder.ftl"
	nameForTest              = "Romain"
	resultForTest            = "negatif"
	localeForTest            = "fr"
	filename1ForTest         = "document.txt"
	contentType1ForTest      = "text/plain"
	content1ForTest          = "Q2VjaSBlc3QgdW4gZG9jdW1lbnQgdGV4dGUgYXR0YWNow6kgw6AgdW4gbWFpbA=="
	filename2ForTest         = "empty.pdf"
	contentType2ForTest      = "application/pdf"
	content2ForTest          = "JVBERi0xLjQKJdPr6eEKMSAwIG9iago8PC9DcmVhdG9yIChNb3ppbGxhLzUuMCBcKFd"

	themingForTest = api.EmailThemingRepresentation{
		SubjectKey:        &subjectKeyForTest,
		SubjectParameters: &subjectParametersForTest,
		Template:          &templateForTest,
		Locale:            &localeForTest,
	}

	attachment1ForTest = api.AttachementRepresentation{
		Filename:    &filename1ForTest,
		ContentType: &content1ForTest,
		Content:     &content1ForTest,
	}
	attachment2ForTest = api.AttachementRepresentation{
		Filename:    &filename2ForTest,
		ContentType: &content2ForTest,
		Content:     &content2ForTest,
	}
	attachmentsForTest = []api.AttachementRepresentation{attachment1ForTest, attachment2ForTest}

	emailForTest = api.EmailRepresentation{
		Recipient:   &recipientForTest,
		Theming:     &themingForTest,
		Attachments: &attachmentsForTest,
	}

	emailForTestNilAttachments = api.EmailRepresentation{
		Recipient:   &recipientForTest,
		Theming:     &themingForTest,
		Attachments: nil,
	}

	themingForTestKC = kc.EmailThemingRepresentation{
		SubjectKey:        &subjectKeyForTest,
		SubjectParameters: &subjectParametersForTest,
		Template:          &templateForTest,
		Locale:            &localeForTest,
	}

	attachment1ForTestKC = kc.AttachementRepresentation{
		Filename:    &filename1ForTest,
		ContentType: &content1ForTest,
		Content:     &content1ForTest,
	}
	attachment2ForTestKC = kc.AttachementRepresentation{
		Filename:    &filename2ForTest,
		ContentType: &content2ForTest,
		Content:     &content2ForTest,
	}
	attachmentsForTestKC = []kc.AttachementRepresentation{attachment1ForTestKC, attachment2ForTestKC}

	emailForTestKC = kc.EmailRepresentation{
		Recipient:   &recipientForTest,
		Theming:     &themingForTestKC,
		Attachments: &attachmentsForTestKC,
	}

	emailForTestNilAttachmentsKC = kc.EmailRepresentation{
		Recipient:   &recipientForTest,
		Theming:     &themingForTestKC,
		Attachments: nil,
	}
)

var (
	msisdnForTest            = "+41791234567"
	messageKeyForTest        = "test-result"
	messageParametersForTest = []string{"Walter", "negative"}

	smsForTest = api.SMSRepresentation{
		MSISDN: &msisdnForTest,
		Theming: &api.SMSThemingRepresentation{
			MessageKey:        &messageKeyForTest,
			MessageParameters: &messageParametersForTest,
			Locale:            &localeForTest,
		},
	}
	smsForTestNilTheming = api.SMSRepresentation{
		MSISDN:  &msisdnForTest,
		Theming: nil,
	}

	smsForTestKC = kc.SMSRepresentation{
		MSISDN: &msisdnForTest,
		Theming: &kc.SMSThemingRepresentation{
			MessageKey:        &messageKeyForTest,
			MessageParameters: &messageParametersForTest,
			Locale:            &localeForTest,
		},
	}
	smsForTestNilThemingKC = kc.SMSRepresentation{
		MSISDN:  &msisdnForTest,
		Theming: nil,
	}
)

func createMocks(mockCtrl *gomock.Controller) componentMocks {
	return componentMocks{
		keycloakCommunicationsClient: mock.NewKeycloakCommunicationsClient(mockCtrl),
		logger:                       mock.NewLogger(mockCtrl),
	}
}

func createComponent(mocks componentMocks) Component {
	return NewComponent(mocks.keycloakCommunicationsClient, mocks.logger)
}

func TestSendEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakCommunicationsClient = mock.NewKeycloakCommunicationsClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var communicationsComponent = NewComponent(mockKeycloakCommunicationsClient, mockLogger)

	var accessToken = "TOKEN=="
	var reqRealm = "reqRealm"

	{
		mockKeycloakCommunicationsClient.EXPECT().SendEmail(accessToken, "reqRealm", "targetRealm", emailForTestKC).Return(nil).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		err := communicationsComponent.SendEmail(ctx, "targetRealm", emailForTest)
		assert.Nil(t, err)
	}

	{
		mockKeycloakCommunicationsClient.EXPECT().SendEmail(accessToken, "reqRealm", "targetRealm", emailForTestKC).Return(fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		mockLogger.EXPECT().Warn(ctx, "err", "Unexpected error")

		err := communicationsComponent.SendEmail(ctx, "targetRealm", emailForTest)
		assert.NotNil(t, err)
	}

}

func TestSendEmailToUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakCommunicationsClient = mock.NewKeycloakCommunicationsClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var communicationsComponent = NewComponent(mockKeycloakCommunicationsClient, mockLogger)

	var accessToken = "TOKEN=="
	var reqRealm = "reqRealm"
	var userID = "testerID"

	{
		mockKeycloakCommunicationsClient.EXPECT().SendEmailToUser(accessToken, "reqRealm", "targetRealm", userID, emailForTestKC).Return(nil).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		err := communicationsComponent.SendEmailToUser(ctx, "targetRealm", userID, emailForTest)
		assert.Nil(t, err)
	}

	{
		mockKeycloakCommunicationsClient.EXPECT().SendEmailToUser(accessToken, "reqRealm", "targetRealm", userID, emailForTestKC).Return(fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		mockLogger.EXPECT().Warn(ctx, "err", "Unexpected error")

		err := communicationsComponent.SendEmailToUser(ctx, "targetRealm", userID, emailForTest)
		assert.NotNil(t, err)
	}

}

func TestSendSMS(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakCommunicationsClient = mock.NewKeycloakCommunicationsClient(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var communicationsComponent = NewComponent(mockKeycloakCommunicationsClient, mockLogger)

	var accessToken = "TOKEN=="
	var reqRealm = "reqRealm"

	{
		mockKeycloakCommunicationsClient.EXPECT().SendSMS(accessToken, "targetRealm", smsForTestKC).Return(nil).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		err := communicationsComponent.SendSMS(ctx, "targetRealm", smsForTest)
		assert.Nil(t, err)
	}

	{
		mockKeycloakCommunicationsClient.EXPECT().SendSMS(accessToken, "targetRealm", smsForTestKC).Return(fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		mockLogger.EXPECT().Warn(ctx, "err", "Unexpected error")

		err := communicationsComponent.SendSMS(ctx, "targetRealm", smsForTest)
		assert.NotNil(t, err)
	}

}
