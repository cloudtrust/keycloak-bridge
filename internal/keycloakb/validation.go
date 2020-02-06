package keycloakb

import (
	"regexp"
	"strings"
	"time"

	cerrors "github.com/cloudtrust/common-service/errors"
	"github.com/nyaruka/phonenumbers"
)

type Validator interface {
	ValidateParameterIn(prmName string, value *string, allowedValues map[string]bool, mandatory bool) Validator
	ValidateParameterRegExp(prmName string, value *string, regExp string, mandatory bool) Validator
	ValidateParameterPhoneNumber(prmName string, value *string) Validator
	ValidateParameterDate(prmName string, value *string, dateLayout string, mandatory bool) Validator
	Status() error
}

type successValidator struct {
}

type failedValidator struct {
	err error
}

// NewParameterValidator creates a validator ready to check multiple parameters
func NewParameterValidator() Validator {
	return &successValidator{}
}

func (v *successValidator) ValidateParameterIn(prmName string, value *string, allowedValues map[string]bool, mandatory bool) Validator {
	if value == nil {
		if mandatory {
			return &failedValidator{err: cerrors.CreateMissingParameterError(prmName)}
		}
	} else {
		if _, ok := allowedValues[*value]; !ok {
			return &failedValidator{err: cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)}
		}
	}
	return v
}

func (v *successValidator) ValidateParameterRegExp(prmName string, value *string, regExp string, mandatory bool) Validator {
	if value == nil {
		if mandatory {
			return &failedValidator{err: cerrors.CreateMissingParameterError(prmName)}
		}
	} else {
		res, _ := regexp.MatchString(regExp, strings.ToLower(*value))
		if !res {
			return &failedValidator{err: cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)}
		}
	}
	return v
}

func (v *successValidator) ValidateParameterPhoneNumber(prmName string, value *string) Validator {
	if value == nil {
		return &failedValidator{err: cerrors.CreateMissingParameterError(prmName)}
	}
	var metadata, err = phonenumbers.Parse(*value, "CH")
	if err != nil || !phonenumbers.IsPossibleNumber(metadata) {
		return &failedValidator{err: cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)}
	}
	return v
}

func (v *successValidator) ValidateParameterDate(prmName string, value *string, dateLayout string, mandatory bool) Validator {
	if value == nil {
		if mandatory {
			return &failedValidator{err: cerrors.CreateMissingParameterError(prmName)}
		}
	} else {
		var _, err = time.Parse(dateLayout, *value)
		if err != nil {
			return &failedValidator{err: cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)}
		}
	}
	return v
}

func (v *successValidator) Status() error {
	return nil
}

func (v *failedValidator) ValidateParameterIn(prmName string, value *string, allowedValues map[string]bool, mandatory bool) Validator {
	return v
}

func (v *failedValidator) ValidateParameterRegExp(prmName string, value *string, regExp string, mandatory bool) Validator {
	return v
}

func (v *failedValidator) ValidateParameterPhoneNumber(prmName string, value *string) Validator {
	return v
}

func (v *failedValidator) ValidateParameterDate(prmName string, value *string, dateLayout string, mandatory bool) Validator {
	return v
}

func (v *failedValidator) Status() error {
	return v.err
}

// ValidateParameterIn validates that a value is a key of the given map
func ValidateParameterIn(prmName string, value *string, allowedValues map[string]bool, mandatory bool) error {
	if value == nil {
		if mandatory {
			return cerrors.CreateMissingParameterError(prmName)
		}
	} else {
		if _, ok := allowedValues[*value]; !ok {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
		}
	}
	return nil
}

// ValidateParameterRegExp validates that a value matches a regular expression
func ValidateParameterRegExp(prmName string, value *string, regExp string, mandatory bool) error {
	if value == nil {
		if mandatory {
			return cerrors.CreateMissingParameterError(prmName)
		}
	} else {
		res, _ := regexp.MatchString(regExp, strings.ToLower(*value))
		if !res {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
		}
	}
	return nil
}

// ValidateParameterPhoneNumber validates a phone number (lib phonenumbes is based on the Java library libphonenumber)
func ValidateParameterPhoneNumber(prmName string, value *string) error {
	if value == nil {
		return cerrors.CreateMissingParameterError(prmName)
	}
	var metadata, err = phonenumbers.Parse(*value, "CH")
	if err != nil || !phonenumbers.IsPossibleNumber(metadata) {
		return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
	}
	return nil
}

// ValidateParameterDate validates a date in a string
func ValidateParameterDate(prmName string, value *string, dateLayout string, mandatory bool) error {
	if value == nil {
		if mandatory {
			return cerrors.CreateMissingParameterError(prmName)
		}
	} else {
		var _, err = time.Parse(dateLayout, *value)
		if err != nil {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
		}
	}
	return nil
}
