package dto

import (
	"time"

	"github.com/cloudtrust/common-service/v2/fields"
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

func toFieldValue(value *string) []string {
	if value != nil {
		return []string{*value}
	}
	return nil
}

func (dbu *DBUser) GetFieldValues(field fields.Field) []string {
	switch field {
	case fields.BirthLocation:
		return toFieldValue(dbu.BirthLocation)
	case fields.Nationality:
		return toFieldValue(dbu.Nationality)
	case fields.IDDocumentType:
		return toFieldValue(dbu.IDDocumentType)
	case fields.IDDocumentNumber:
		return toFieldValue(dbu.IDDocumentNumber)
	case fields.IDDocumentExpiration:
		return toFieldValue(dbu.IDDocumentExpiration)
	case fields.IDDocumentCountry:
		return toFieldValue(dbu.IDDocumentCountry)
	}
	return nil
}
