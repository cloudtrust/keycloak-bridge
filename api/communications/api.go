package apicommunications

// CPREmailRepresentation struct
type CPREmailRepresentation struct {
	Recipient   *string                         `json:"recipient,omitempty"`
	Theming     *CPREmailThemingRepresentation  `json:"theming,omitempty"`
	Attachments *[]CPRAttachementRepresentation `json:"attachments,omitempty"`
}

// CPREmailThemingRepresentation struct
type CPREmailThemingRepresentation struct {
	SubjectKey         *string                              `json:"subjectKey,omitempty"`
	SubjectParameters  *[]string                            `json:"subjectParameters,omitempty"`
	Template           *string                              `json:"template,omitempty"`
	TemplateParameters *CPRTemplateParametersRepresentation `json:"templateParameters,omitempty"`
	Locale             *string                              `json:"locale,omitempty"`
}

// CPRTemplateParametersRepresentation struct
type CPRTemplateParametersRepresentation struct {
	Name   *string `json:"name,omitepmty"`
	Result *string `json:"result,omitepmty"`
}

// CPRAttachementRepresentation struct
type CPRAttachementRepresentation struct {
	Filename    *string `json:"filename,omitempty"`
	ContentType *string `json:"contentType,omitempty"`
	Content     *string `json:"content,omitempty"`
}

// CPRSMSRepresentation struct
type CPRSMSRepresentation struct {
	MSISDN  *string                      `json:"msisdn,omitempty"`
	Theming *CPRSMSThemingRepresentation `json:"theming,omitempty"`
}

// CPRSMSThemingRepresentation struct
type CPRSMSThemingRepresentation struct {
	MessageKey        *string   `json:"messageKey,omitempty"`
	MessageParameters *[]string `json:"messageParameters,omitempty"`
	Locale            *string   `json:"locale,omitempty"`
}
