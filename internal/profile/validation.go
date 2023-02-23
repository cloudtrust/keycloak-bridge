package profile

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"

	cs "github.com/cloudtrust/common-service/v2"
	cerrors "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

const (
	regexEmail                     = "[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*"
	regexUsernameProhibited        = "^[^<>&\"'\\s\\v\\h$%!#?§,;:*~/\\\\|^=\\[\\]{}()`\\p{Cntrl}]+$"
	regexPersonNameProhibitedChars = "^[^<>&\"\\v$%!#?§;*~/\\\\|^=\\[\\]{}()\\p{Cntrl}]+$"

	requesterType = "user"
)

// UserProfile interface
type UserProfile interface {
	GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error)
}

// ContainsFields interface
type ContainsFields interface {
	GetField(name string) interface{}
	SetField(name string, value interface{})
}

func toErrName(value string) string {
	return strings.Replace(value, "ENC_", "", 1)
}

// IsAttributeRequired tells if attribute is required
func IsAttributeRequired(attrb kc.ProfileAttrbRepresentation, frontend string) bool {
	if attrb.AnnotationMatches(frontend, func(value string) bool {
		return strings.EqualFold(value, "required")
	}) {
		return true
	}
	if attrb.Required == nil {
		return false
	}
	return validation.IsStringInSlice(attrb.Required.Roles, requesterType)
}

// Validate validates an incoming account against a user profile
func Validate(ctx context.Context, upc UserProfile, realm string, input ContainsFields, apiName string, checkMandatory bool) error {
	// Get the UserProfile
	var userProfile kc.UserProfileRepresentation
	var err error
	if userProfile, err = upc.GetRealmUserProfile(ctx, realm); err != nil {
		return err
	}
	// Validate input request
	return ValidateUser(userProfile, input, apiName, checkMandatory)
}

// ValidateUser against a given profile
func ValidateUser(profile kc.UserProfileRepresentation, input ContainsFields, apiName string, checkMandatory bool) error {
	for _, attrb := range profile.Attributes {
		if !attrb.AnnotationMatches(apiName, func(value string) bool {
			return strings.EqualFold(value, "true") || strings.EqualFold(value, "required")
		}) {
			// Attribute is not supposed to be provided for this frontend type
			input.SetField(*attrb.Name, nil)
		} else {
			var value = input.GetField(*attrb.Name)
			if value == nil {
				if checkMandatory && IsAttributeRequired(attrb, apiName) {
					return cerrors.CreateBadRequestError(cerrors.MsgErrMissingParam + "." + toErrName(*attrb.Name))
				}
			} else if err := validateAttribute(attrb, value); err != nil {
				return err
			}
		}
	}
	return nil
}

var mapNameToValidator = map[string]func(kc.ProfileAttrbRepresentation, kc.ProfileAttrValidatorRepresentation, interface{}) error{
	// Keycloak validators
	"email":                             validateAttributeEmail,
	"integer":                           validateAttributeInteger,
	"double":                            validateAttributeDouble,
	"length":                            validateAttributeLength,
	"pattern":                           validateAttributePattern,
	"options":                           validateAttributeOptions,
	"uri":                               validateAttributeURI,
	"local-date":                        validateAttributeLocalDate,
	"username-prohibited-characters":    validateAttributeUsernameProhibitedChars,
	"person-name-prohibited-characters": validateAttributePersonNameProhibitedChars,
	// Cloudtrust validators
	"ct-date":        validateAttributeCtDate,
	"ct-pattern":     validateAttributeCtMultiRegex,
	"ct-phonenumber": validateAttributeCtPhoneNumber,
}

func validateAttribute(attrb kc.ProfileAttrbRepresentation, value interface{}) error {
	for key, validator := range attrb.Validations {
		if fn, ok := mapNameToValidator[key]; ok {
			if err := fn(attrb, validator, value); err != nil {
				return err
			}
		} else {
			return cerrors.CreateInternalServerError("unknownValidator." + key)
		}
	}
	return nil
}

// Ensure value is not nil before calling this
func validateAttributeEmail(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	switch v := value.(type) {
	case string:
		return validateRegexWithString(attrb, regexEmail, v)
	case *string:
		return validateRegexWithString(attrb, regexEmail, *v)
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
}

// Ensure value is not nil before calling this
func validateAttributeInteger(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var intValue = cs.ToInt(value, math.MinInt)
	if intValue == math.MinInt {
		return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
	}
	return validateRangeWithString(attrb, validator, intValue)
}

// Ensure value is not nil before calling this
func validateAttributeDouble(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var infinity = math.Inf(-1)
	var floatValue = cs.ToFloat(value, infinity)
	if floatValue == infinity {
		return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
	}
	for k, v := range validator {
		if k == "min" {
			if floatValue < cs.ToFloat(v, floatValue+1.0) {
				return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
			}
		} else if k == "max" {
			if floatValue > cs.ToFloat(v, floatValue-1.0) {
				return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
			}
		}
	}
	return nil
}

// Ensure value is not nil before calling this
func validateAttributeLength(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	switch v := value.(type) {
	case string:
		return validateRangeWithString(attrb, validator, len(v))
	case *string:
		return validateRangeWithString(attrb, validator, len(*v))
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
}

// Ensure value is not nil before calling this
func validateAttributePattern(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var regex = validator["pattern"].(string)
	switch v := value.(type) {
	case string:
		return validateRegexWithString(attrb, regex, v)
	case *string:
		return validateRegexWithString(attrb, regex, *v)
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
}

// Ensure value is not nil before calling this
func validateAttributeUsernameProhibitedChars(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	return validateAttributePattern(attrb, kc.ProfileAttrValidatorRepresentation{
		"pattern": regexUsernameProhibited,
	}, value)
}

// Ensure value is not nil before calling this
func validateAttributePersonNameProhibitedChars(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	return validateAttributePattern(attrb, kc.ProfileAttrValidatorRepresentation{
		"pattern": regexPersonNameProhibitedChars,
	}, value)
}

// Ensure value is not nil before calling this
func validateAttributeOptions(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var valueStr string
	switch v := value.(type) {
	case string:
		valueStr = v
	case *string:
		valueStr = *v
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
	for _, opt := range validator["options"].([]interface{}) {
		if valueStr == opt.(string) {
			return nil
		}
	}
	return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
}

// Ensure value is not nil before calling this
func validateAttributeURI(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	switch v := value.(type) {
	case string:
		return validateRegexWithString(attrb, constants.RegExpRedirectURI, v)
	case *string:
		return validateRegexWithString(attrb, constants.RegExpRedirectURI, *v)
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
}

// Ensure value is not nil before calling this
func validateAttributeLocalDate(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var ctValidate = validation.NewParameterValidator()
	switch v := value.(type) {
	case string:
		return ctValidate.ValidateParameterDateMultipleLayout(*attrb.Name, &v, constants.SupportedDateLayouts, false).Status()
	case *string:
		return ctValidate.ValidateParameterDateMultipleLayout(*attrb.Name, v, constants.SupportedDateLayouts, false).Status()
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
}

func validateRegexWithString(attrb kc.ProfileAttrbRepresentation, regex string, value string) error {
	// Java: \p{L} Golang: \p{Lu}\p{Ll}
	// Replaces Java regex not recognized by Golang
	regex = strings.ReplaceAll(regex, `\h`, `\s`)                   // Horizontal spaces
	regex = strings.ReplaceAll(regex, `\v`, `\s`)                   // Vertical spaces
	regex = strings.ReplaceAll(regex, `\p{Cntrl}`, `\x00-\x1F\x7F`) // Control characters
	res, _ := regexp.MatchString(regex, value)
	if !res {
		return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
	}
	return nil
}

func validateAttributeCtDate(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var ctValidate = validation.NewParameterValidator()
	var ptrDate *string
	switch v := value.(type) {
	case string:
		ptrDate = &v
	case *string:
		ptrDate = v
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
	if cfg, ok := validator["past"]; ok && "true" == cfg.(string) {
		ctValidate = ctValidate.ValidateParameterDateBeforeMultipleLayout(*attrb.Name, ptrDate, constants.SupportedDateLayouts, time.Now(), false)
	} else if cfg, ok := validator["future"]; ok && "true" == cfg.(string) {
		ctValidate = ctValidate.ValidateParameterDateAfterMultipleLayout(*attrb.Name, ptrDate, constants.SupportedDateLayouts, time.Now(), false)
	} else {
		ctValidate = ctValidate.ValidateParameterDateMultipleLayout(*attrb.Name, ptrDate, constants.SupportedDateLayouts, false)
	}
	return ctValidate.Status()
}

func validateAttributeCtMultiRegex(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var regex string
	if value, ok := validator["pattern.go"]; ok {
		regex = value.(string)
	} else {
		regex = validator["pattern"].(string)
	}
	switch v := value.(type) {
	case string:
		return validateRegexWithString(attrb, regex, v)
	case *string:
		return validateRegexWithString(attrb, regex, *v)
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
}

func validateAttributeCtPhoneNumber(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, value interface{}) error {
	var ctValidate = validation.NewParameterValidator()
	switch v := value.(type) {
	case string:
		return ctValidate.ValidateParameterPhoneNumber(*attrb.Name, &v, true).Status()
	case *string:
		return ctValidate.ValidateParameterPhoneNumber(*attrb.Name, v, true).Status()
	default:
		// Should not happen if correctly implemented
		return cerrors.CreateInternalServerError("unknownInputType")
	}
}

func validateRangeWithString(attrb kc.ProfileAttrbRepresentation, validator kc.ProfileAttrValidatorRepresentation, referenceValue int) error {
	for k, v := range validator {
		if k == "min" {
			var attributeValue = cs.ToInt(v, referenceValue+1) // Use a too high value by default to make the test fails
			if referenceValue < attributeValue {
				return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
			}
		} else if k == "max" {
			var attributeValue = cs.ToInt(v, referenceValue-1) // Use a too low value by default to make the test fails
			if referenceValue > attributeValue {
				return cerrors.CreateBadRequestError(cerrors.MsgErrInvalidParam + "." + toErrName(*attrb.Name))
			}
		}
	}
	return nil
}

func IfNotNil(value *string) interface{} {
	if value == nil {
		return nil
	}
	return value
}

func IfTimePtrNotNil(value *time.Time) interface{} {
	if value == nil {
		return nil
	}
	return value
}
