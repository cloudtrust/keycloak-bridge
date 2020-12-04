package apicommunications

import (
	"encoding/json"
	"strings"

	kc "github.com/cloudtrust/keycloak-client"
)

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

// ExportToKeycloak exports the email representation into a Keycloak email representation
func (r *EmailRepresentation) ExportToKeycloak(kcRep *kc.EmailRepresentation) {
	// We set everything to nil to be safe
	kcRep.Recipient = nil
	kcRep.Theming = nil
	kcRep.Attachments = nil
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
}

// ImportFromKeycloak imports the email representation from a Keycloak email representation
func (r *EmailRepresentation) ImportFromKeycloak(kcRep *kc.EmailRepresentation) {
	// We set everything to nil to be safe
	r.Recipient = nil
	r.Theming = nil
	r.Attachments = nil
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
}

// EmailFromJSON creates an email using its json representation
func EmailFromJSON(jsonRep string) (EmailRepresentation, error) {
	var email EmailRepresentation
	dec := json.NewDecoder(strings.NewReader(jsonRep))
	dec.DisallowUnknownFields()
	err := dec.Decode(&email)
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

// ExportToKeycloak exports the SMS representation into a Keycloak SMS representation
func (r *SMSRepresentation) ExportToKeycloak(kcRep *kc.SMSRepresentation) {
	// We set everything to nil to be safe
	kcRep.MSISDN = nil
	kcRep.Theming = nil
	if r.MSISDN != nil {
		kcRep.MSISDN = r.MSISDN
	}
	if r.Theming != nil {
		kcRep.Theming = &kc.SMSThemingRepresentation{}
		kcRep.Theming.MessageKey = r.Theming.MessageKey
		kcRep.Theming.MessageParameters = r.Theming.MessageParameters
		kcRep.Theming.Locale = r.Theming.Locale
	}
}

// ImportFromKeycloak exports the SMS representation into a Keycloak SMS representation
func (r *SMSRepresentation) ImportFromKeycloak(kcRep *kc.SMSRepresentation) {
	// We set everything to nil to be safe
	r.MSISDN = nil
	r.Theming = nil
	if kcRep.MSISDN != nil {
		r.MSISDN = kcRep.MSISDN
	}
	if kcRep.Theming != nil {
		r.Theming = &SMSThemingRepresentation{}
		r.Theming.MessageKey = kcRep.Theming.MessageKey
		r.Theming.MessageParameters = kcRep.Theming.MessageParameters
		r.Theming.Locale = kcRep.Theming.Locale
	}
}

// SMSFromJSON creates an sms using its json representation
func SMSFromJSON(jsonRep string) (SMSRepresentation, error) {
	var sms SMSRepresentation
	dec := json.NewDecoder(strings.NewReader(jsonRep))
	dec.DisallowUnknownFields()
	err := dec.Decode(&sms)
	return sms, err
}

// SMSToJSON returns a json representation of a given SMS
func (r *SMSRepresentation) SMSToJSON() string {
	var bytes, _ = json.Marshal(r)
	return string(bytes)
}
