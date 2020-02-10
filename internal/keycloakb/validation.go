package keycloakb

import (
	"regexp"
	"strings"
	"time"

	cerrors "github.com/cloudtrust/common-service/errors"
	"github.com/nyaruka/phonenumbers"
)

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
func ValidateParameterPhoneNumber(prmName string, value *string, mandatory bool) error {
	if value == nil {
		if mandatory {
			return cerrors.CreateMissingParameterError(prmName)
		}
	} else {
		var metadata, err = phonenumbers.Parse(*value, "CH")
		if err != nil || !phonenumbers.IsPossibleNumber(metadata) {
			return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + prmName)
		}
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
