package apicommunications

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	themingForTest = EmailThemingRepresentation{
		SubjectKey:        &subjectKeyForTest,
		SubjectParameters: &subjectParametersForTest,
		Template:          &templateForTest,
		Locale:            &localeForTest,
	}

	attachment1ForTest = AttachementRepresentation{
		Filename:    &filename1ForTest,
		ContentType: &content1ForTest,
		Content:     &content1ForTest,
	}
	attachment2ForTest = AttachementRepresentation{
		Filename:    &filename2ForTest,
		ContentType: &content2ForTest,
		Content:     &content2ForTest,
	}
	attachmentsForTest = []AttachementRepresentation{attachment1ForTest, attachment2ForTest}

	emailForTest = EmailRepresentation{
		Recipient:   &recipientForTest,
		Theming:     &themingForTest,
		Attachments: &attachmentsForTest,
	}

	emailForTestNilAttachments = EmailRepresentation{
		Recipient:   &recipientForTest,
		Theming:     &themingForTest,
		Attachments: nil,
	}
)

func TestJSONEmail(t *testing.T) {
	j := emailForTest.EmailToJSON()
	emailFromJ, err := EmailFromJSON(j)
	assert.Nil(t, err)
	assert.Equal(t, emailForTest, emailFromJ)

	_, err = EmailFromJSON(`{"recipient": "recipient@domain.ch",`)
	assert.NotNil(t, err)
	_, err = EmailFromJSON(`{"recipient": "recipient@domain.ch", unknownField="foo"}`)
	assert.NotNil(t, err)
}

func TestExportEmailToKeycloakImportEmailFromKeycloak(t *testing.T) {
	kcRep := ExportEmailToKeycloak(&emailForTest)
	email := ImportEmailFromKeycloak(kcRep)

	assert.Equal(t, emailForTest, *email)

	kcRep = ExportEmailToKeycloak(&emailForTestNilAttachments)
	email = ImportEmailFromKeycloak(kcRep)

	assert.Equal(t, emailForTestNilAttachments, *email)
}

var (
	msisdnForTest            = "+41791234567"
	messageKeyForTest        = "test-result"
	messageParametersForTest = []string{"Walter", "negative"}

	smsForTest = SMSRepresentation{
		MSISDN: &msisdnForTest,
		Theming: &SMSThemingRepresentation{
			MessageKey:        &messageKeyForTest,
			MessageParameters: &messageParametersForTest,
			Locale:            &localeForTest,
		},
	}
	smsForTestNilTheming = SMSRepresentation{
		MSISDN:  &msisdnForTest,
		Theming: nil,
	}
)

func TestJSONSMS(t *testing.T) {
	j := smsForTest.SMSToJSON()
	smsFromJ, err := SMSFromJSON(j)
	assert.Nil(t, err)
	assert.Equal(t, smsForTest, smsFromJ)

	_, err = SMSFromJSON(`{"msisdn": "+41791234567",`)
	assert.NotNil(t, err)
	_, err = SMSFromJSON(`{"msisdn": "+41791234567", unknownField="foo"}`)
	assert.NotNil(t, err)
}

func TestExportSMSToKeycloakImportSMSFromKeycloak(t *testing.T) {
	kcRep := ExportSMSToKeycloak(&smsForTest)
	sms := ImportSMSFromKeycloak(kcRep)

	assert.Equal(t, smsForTest, *sms)

	kcRep = ExportSMSToKeycloak(&smsForTestNilTheming)
	sms = ImportSMSFromKeycloak(kcRep)

	assert.Equal(t, smsForTestNilTheming, *sms)
}
