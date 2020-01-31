package dto

import (
	"time"
)

const (
	dateLayout = "02.01.2006"
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

// LastValidation gives the date of the last validation (if any)
func (u *DBUser) LastValidation() *string {
	var nbValidations = len(u.Validations)
	if nbValidations == 0 {
		return nil
	}

	var validation = u.Validations[nbValidations-1]
	var date = validation.Date.Format(dateLayout)
	return &date
}
