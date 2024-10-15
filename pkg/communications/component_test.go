package communications

import (
	"context"
	"errors"
	"fmt"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	api "github.com/cloudtrust/keycloak-bridge/api/communications"
	"github.com/cloudtrust/keycloak-bridge/pkg/communications/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	keycloakCommunicationsClient *mock.KeycloakCommunicationsClient
	tokenProvider                *mock.OidcTokenProvider
	logger                       *mock.Logger
}

var (
	recipientForTest         = "recipient@domain.ch"
	subjectKeyForTest        = "expiryreminder.subject"
	subjectParametersForTest = []string{"my-value"}
	templateForTest          = "expiry-reminder.ftl"
	localeForTest            = "fr"
	filename1ForTest         = "document.txt"
	content1ForTest          = "Q2VjaSBlc3QgdW4gZG9jdW1lbnQgdGV4dGUgYXR0YWNow6kgw6AgdW4gbWFpbA=="
	filename2ForTest         = "empty.pdf"
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
		tokenProvider:                mock.NewOidcTokenProvider(mockCtrl),
		logger:                       mock.NewLogger(mockCtrl),
	}
}

func createComponent(mocks componentMocks) Component {
	return NewComponent(mocks.keycloakCommunicationsClient, mocks.tokenProvider, mocks.logger)
}

func TestSendEmail(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mocks                   = createMocks(mockCtrl)
		communicationsComponent = createComponent(mocks)

		accessToken = "TOKEN=="
		reqRealm    = "reqRealm"
		ctx         = context.TODO()
	)
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

	t.Run("Can't get OIDC token", func(t *testing.T) {
		dummyErr := errors.New("dummy")
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(gomock.Any(), "targetRealm").Return("", dummyErr)
		mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		err := communicationsComponent.SendEmail(ctx, "targetRealm", emailForTest)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideTokenForRealm(gomock.Any(), "targetRealm").Return(accessToken, nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakCommunicationsClient.EXPECT().SendEmail(accessToken, "reqRealm", "targetRealm", emailForTestKC).Return(nil)
		err := communicationsComponent.SendEmail(ctx, "targetRealm", emailForTest)
		assert.Nil(t, err)
	})

	t.Run("Failure", func(t *testing.T) {
		mocks.keycloakCommunicationsClient.EXPECT().SendEmail(accessToken, "reqRealm", "targetRealm", emailForTestKC).Return(fmt.Errorf("Unexpected error"))
		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")

		err := communicationsComponent.SendEmail(ctx, "targetRealm", emailForTest)
		assert.NotNil(t, err)
	})
}

func TestSendEmailToUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	communicationsComponent := createComponent(mocks)

	accessToken := "TOKEN=="
	reqRealm := "reqRealm"
	userID := "testerID"

	t.Run("Can't get OIDC token", func(t *testing.T) {
		dummyErr := errors.New("dummy")
		ctx := context.WithValue(context.Background(), cs.CtContextRealm, reqRealm)

		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(gomock.Any(), "targetRealm").Return("", dummyErr)
		mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := communicationsComponent.SendEmailToUser(ctx, "targetRealm", userID, emailForTest)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideTokenForRealm(gomock.Any(), "targetRealm").Return(accessToken, nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakCommunicationsClient.EXPECT().SendEmailToUser(accessToken, "reqRealm", "targetRealm", userID, emailForTestKC).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		err := communicationsComponent.SendEmailToUser(ctx, "targetRealm", userID, emailForTest)
		assert.Nil(t, err)
	})

	t.Run("Failure case", func(t *testing.T) {
		mocks.keycloakCommunicationsClient.EXPECT().SendEmailToUser(accessToken, "reqRealm", "targetRealm", userID, emailForTestKC).Return(fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")

		err := communicationsComponent.SendEmailToUser(ctx, "targetRealm", userID, emailForTest)
		assert.NotNil(t, err)
	})
}

func TestSendSMS(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	communicationsComponent := createComponent(mocks)

	accessToken := "TOKEN=="
	reqRealm := "reqRealm"

	t.Run("Can't get OIDC token", func(t *testing.T) {
		dummyErr := errors.New("dummy")
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(gomock.Any(), "targetRealm").Return("", dummyErr)
		mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		err := communicationsComponent.SendSMS(context.TODO(), "targetRealm", smsForTest)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideTokenForRealm(gomock.Any(), "targetRealm").Return(accessToken, nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakCommunicationsClient.EXPECT().SendSMS(accessToken, "targetRealm", smsForTestKC).Return(nil)

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		err := communicationsComponent.SendSMS(ctx, "targetRealm", smsForTest)
		assert.Nil(t, err)
	})

	t.Run("Failure", func(t *testing.T) {
		mocks.keycloakCommunicationsClient.EXPECT().SendSMS(accessToken, "targetRealm", smsForTestKC).Return(fmt.Errorf("Unexpected error"))

		ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, reqRealm)

		mocks.logger.EXPECT().Warn(ctx, "err", "Unexpected error")

		err := communicationsComponent.SendSMS(ctx, "targetRealm", smsForTest)
		assert.NotNil(t, err)
	})
}
