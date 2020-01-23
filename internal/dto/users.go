package dto

import (
	"time"
)

// DBUser struct
type DBUser struct {
	UserID               *string        `json:"-"`
	BirthLocation        *string        `json:"birth_location,omitempty"`
	IDDocumentType       *string        `json:"id_document_typ,omitempty"`
	IDDocumentNumber     *string        `json:"id_document_num,omitempty"`
	IDDocumentExpiration *string        `json:"id_document_exp,omitempty"`
	Validations          []DBValidation `json:"validations,omitempty"`
}

// DBValidation struct
type DBValidation struct {
	Date         *time.Time `json:"date"`
	OperatorName *string    `json:"operator_name"`
	Comment      *string    `json:"comment,omitempty"`
}
