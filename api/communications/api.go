package apicommunications

import (
	"encoding/json"

	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client"
)

const (
	prmEmailRecipient         = "email_recipient"
	prmEmailTheming           = "email_theming"
	prmEmailThemingSubjectKey = "email_theming_subject_key"
	prmEmailThemingLocale     = "email_theming_template_locale"

	prmSMSMSISDN        = "sms_msisdn"
	prmSMSTheming       = "sms_theming"
	prmSMSThemingLocale = "sms_theming_locale"

	regExpEmail             = constants.RegExpEmail
	regExpThemingSubjectKey = constants.RegExpDescription
	regExpLocale            = constants.RegExpLocale
)

// ActionRepresentation struct
type ActionRepresentation struct {
	Name  *string `json:"name"`
	Scope *string `json:"scope"`
}

// EmailRepresentation struct
type EmailRepresentation struct {
	Recipient   *string                      `json:"recipient,omitempty"`
	Theming     *EmailThemingRepresentation  `json:"theming,omitempty"`
	Attachments *[]AttachementRepresentation `json:"attachments,omitempty"`
}

// EmailThemingRepresentation struct
type EmailThemingRepresentation struct {
	SubjectKey         *string            `json:"subjectKey,omitempty"`
	SubjectParameters  *[]string          `json:"subjectParameters,omitempty"`
	Template           *string            `json:"template,omitempty"`
	TemplateParameters *map[string]string `json:"templateParameters,omitempty"`
	Locale             *string            `json:"locale,omitempty"`
}

// AttachementRepresentation struct
type AttachementRepresentation struct {
	Filename    *string `json:"filename,omitempty"`
	ContentType *string `json:"contentType,omitempty"`
	Content     *string `json:"content,omitempty"`
}

// ExportEmailToKeycloak exports the email representation into a Keycloak email representation
func ExportEmailToKeycloak(r *EmailRepresentation) *kc.EmailRepresentation {
	var kcRep kc.EmailRepresentation
	if r == nil {
		return nil
	}
	if r.Recipient != nil {
		kcRep.Recipient = r.Recipient
	}
	if r.Theming != nil {
		kcRep.Theming = &kc.EmailThemingRepresentation{}
		kcRep.Theming.SubjectKey = r.Theming.SubjectKey
		kcRep.Theming.SubjectParameters = r.Theming.SubjectParameters
		kcRep.Theming.Template = r.Theming.Template
		kcRep.Theming.TemplateParameters = r.Theming.TemplateParameters
		kcRep.Theming.Locale = r.Theming.Locale
	}
	if r.Attachments != nil {
		kcRep.Attachments = &[]kc.AttachementRepresentation{}
		for _, a := range *r.Attachments {
			tmp := kc.AttachementRepresentation{
				Filename:    a.Filename,
				ContentType: a.ContentType,
				Content:     a.Content,
			}
			*kcRep.Attachments = append(*kcRep.Attachments, tmp)
		}
	}
	return &kcRep
}

// ImportEmailFromKeycloak imports the email representation from a Keycloak email representation
func ImportEmailFromKeycloak(kcRep *kc.EmailRepresentation) *EmailRepresentation {
	var r EmailRepresentation
	if kcRep == nil {
		return nil
	}
	if kcRep.Recipient != nil {
		r.Recipient = kcRep.Recipient
	}
	if kcRep.Theming != nil {
		r.Theming = &EmailThemingRepresentation{}
		r.Theming.SubjectKey = kcRep.Theming.SubjectKey
		r.Theming.SubjectParameters = kcRep.Theming.SubjectParameters
		r.Theming.Template = kcRep.Theming.Template
		r.Theming.TemplateParameters = kcRep.Theming.TemplateParameters
		r.Theming.Locale = kcRep.Theming.Locale
	}
	if kcRep.Attachments != nil {
		r.Attachments = &[]AttachementRepresentation{}
		for _, a := range *kcRep.Attachments {
			tmp := AttachementRepresentation{
				Filename:    a.Filename,
				ContentType: a.ContentType,
				Content:     a.Content,
			}
			*r.Attachments = append(*r.Attachments, tmp)
		}
	}
	return &r
}

// EmailFromJSON creates an email using its json representation
func EmailFromJSON(jsonRep string) (EmailRepresentation, error) {
	var email EmailRepresentation
	err := json.Unmarshal([]byte(jsonRep), &email)
	return email, err
}

// EmailToJSON returns a json representation of a given Email
func (r *EmailRepresentation) EmailToJSON() string {
	var bytes, _ = json.Marshal(r)
	return string(bytes)
}

// SMSRepresentation struct
type SMSRepresentation struct {
	MSISDN  *string                   `json:"msisdn,omitempty"`
	Theming *SMSThemingRepresentation `json:"theming,omitempty"`
}

// SMSThemingRepresentation struct
type SMSThemingRepresentation struct {
	MessageKey        *string   `json:"messageKey,omitempty"`
	MessageParameters *[]string `json:"messageParameters,omitempty"`
	Locale            *string   `json:"locale,omitempty"`
}

// ExportSMSToKeycloak exports the SMS representation into a Keycloak SMS representation
func ExportSMSToKeycloak(r *SMSRepresentation) *kc.SMSRepresentation {
	var kcRep kc.SMSRepresentation
	if r == nil {
		return nil
	}
	if r.MSISDN != nil {
		kcRep.MSISDN = r.MSISDN
	}
	if r.Theming != nil {
		kcRep.Theming = &kc.SMSThemingRepresentation{}
		kcRep.Theming.MessageKey = r.Theming.MessageKey
		kcRep.Theming.MessageParameters = r.Theming.MessageParameters
		kcRep.Theming.Locale = r.Theming.Locale
	}
	return &kcRep
}

// ImportSMSFromKeycloak exports the SMS representation into a Keycloak SMS representation
func ImportSMSFromKeycloak(kcRep *kc.SMSRepresentation) *SMSRepresentation {
	var r SMSRepresentation
	if kcRep == nil {
		return nil
	}
	if kcRep.MSISDN != nil {
		r.MSISDN = kcRep.MSISDN
	}
	if kcRep.Theming != nil {
		r.Theming = &SMSThemingRepresentation{}
		r.Theming.MessageKey = kcRep.Theming.MessageKey
		r.Theming.MessageParameters = kcRep.Theming.MessageParameters
		r.Theming.Locale = kcRep.Theming.Locale
	}
	return &r
}

// SMSFromJSON creates an sms using its json representation
func SMSFromJSON(jsonRep string) (SMSRepresentation, error) {
	var sms SMSRepresentation
	err := json.Unmarshal([]byte(jsonRep), &sms)
	return sms, err
}

// SMSToJSON returns a json representation of a given SMS
func (r *SMSRepresentation) SMSToJSON() string {
	var bytes, _ = json.Marshal(r)
	return string(bytes)
}

// Validate checks the validity of the given email
func (r *EmailRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp(prmEmailRecipient, r.Recipient, regExpEmail, true).
		ValidateParameterNotNil(prmEmailTheming, r.Theming).
		ValidateParameterRegExp(prmEmailThemingSubjectKey, r.Theming.SubjectKey, regExpThemingSubjectKey, true).
		ValidateParameterRegExp(prmEmailThemingLocale, r.Theming.Locale, regExpLocale, false).
		Status()
}

// Validate checks the validity of the given sms
func (r *SMSRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterPhoneNumber(prmSMSMSISDN, r.MSISDN, true).
		ValidateParameterNotNil(prmSMSTheming, r.Theming).
		ValidateParameterRegExp(prmSMSThemingLocale, r.Theming.Locale, regExpLocale, false).
		Status()
}
