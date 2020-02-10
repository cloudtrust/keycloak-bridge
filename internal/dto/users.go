package dto

import (
	"time"
)

const (
	dateLayout = "02.01.2006"
)

// DBUser struct
type DBUser struct {
	UserID               *string `json:"-"`
	BirthLocation        *string `json:"birth_location,omitempty"`
	IDDocumentType       *string `json:"id_document_typ,omitempty"`
	IDDocumentNumber     *string `json:"id_document_num,omitempty"`
	IDDocumentExpiration *string `json:"id_document_exp,omitempty"`
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
}
