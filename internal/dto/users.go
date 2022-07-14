package dto

import (
	"time"
)

// DBUser struct
type DBUser struct {
	UserID               *string `json:"-"`
	BirthLocation        *string `json:"birth_location,omitempty"`
	Nationality          *string `json:"nationality,omitempty"`
	IDDocumentType       *string `json:"id_document_typ,omitempty"`
	IDDocumentNumber     *string `json:"id_document_num,omitempty"`
	IDDocumentExpiration *string `json:"id_document_exp,omitempty"`
	IDDocumentCountry    *string `json:"id_document_country,omitempty"`
}

// DBCheck struct
type DBCheck struct {
	Operator  *string
	DateTime  *time.Time
	Status    *string
	Type      *string
	Nature    *string
	ProofData *[]byte
	ProofType *string
	Comment   *string
	TxnID     *string
}
