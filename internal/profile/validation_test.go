package profile

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/profile/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func ptr(value string) *string {
	return &value
}

type getfield struct {
	returnValue interface{}
}

var (
	attributeName = "attrbname"
	frontend      = "ft"
)

type UserRepresentation struct {
	Username             *string `json:"username,omitempty"`
	Gender               *string `json:"gender,omitempty"`
	FirstName            *string `json:"firstName,omitempty"`
	LastName             *string `json:"lastName,omitempty"`
	Email                *string `json:"email,omitempty"`
	PhoneNumber          *string `json:"phoneNumber,omitempty"`
	BirthDate            *string `json:"birthDate,omitempty"`
	BirthLocation        *string `json:"birthLocation,omitempty"`
	Nationality          *string `json:"nationality,omitempty"`
	IDDocumentType       *string `json:"idDocumentType,omitempty"`
	IDDocumentNumber     *string `json:"idDocumentNumber,omitempty"`
	IDDocumentExpiration *string `json:"idDocumentExpiration,omitempty"`
	IDDocumentCountry    *string `json:"idDocumentCountry,omitempty"`
	Locale               *string `json:"locale,omitempty"`
	BusinessID           *string `json:"businessId,omitempty"`
}

// GetField implements ContainsFields.
func (ur UserRepresentation) GetField(name string) interface{} {
	switch name {
	case "firstName":
		return ur.FirstName
	case "lastName":
		return ur.LastName
	default:
		return nil
	}
}

// SetField implements ContainsFields.
func (ur UserRepresentation) SetField(name string, value interface{}) {
	switch name {
	case "firstName":
		ur.FirstName = value.(*string)
	case "lastName":
		ur.LastName = value.(*string)
	}
}

func (gf *getfield) GetField(name string) interface{} {
	if attributeName == name {
		return gf.returnValue
	}
	return nil
}

func (gf *getfield) SetField(name string, value interface{}) {
	if attributeName == name {
		gf.returnValue = value
	}
}

func createProfile(key string, validator kc.ProfileAttrValidatorRepresentation, apiName string, required bool) kc.UserProfileRepresentation {
	var res = kc.UserProfileRepresentation{
		Attributes: []kc.ProfileAttrbRepresentation{
			{
				Name: &attributeName,
				Validations: kc.ProfileAttrbValidationRepresentation{
					"length": kc.ProfileAttrValidatorRepresentation{
						"min": "5",
						"max": "20",
					},
				},
				Required: &kc.ProfileAttrbRequiredRepresentation{
					Roles: []string{"dummy-role"},
				},
				Annotations: map[string]string{apiName: "true"},
			},
		},
	}
	if validator != nil {
		res.Attributes[0].Validations[key] = validator
	}
	if required {
		res.Attributes[0].Required.Roles = append(res.Attributes[0].Required.Roles, requesterType)
	}
	return res
}

type mockUserProfile struct {
	err error
}

func (up *mockUserProfile) GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error) {
	return kc.UserProfileRepresentation{}, up.err
}

func TestIsAttributeRequired(t *testing.T) {
	var frontend = "frontend"

	t.Run("Required is nil", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: nil}
		assert.False(t, IsAttributeRequired(attrb, frontend))
	})
	t.Run("Required is nil but annotation tells the attribute is required for the given api", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: nil, Annotations: map[string]string{frontend: "required"}}
		assert.True(t, IsAttributeRequired(attrb, frontend))
	})
	t.Run("Roles is nil", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: &kc.ProfileAttrbRequiredRepresentation{Roles: nil}}
		assert.False(t, IsAttributeRequired(attrb, frontend))
	})
	t.Run("Roles does not contain requesterType", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: &kc.ProfileAttrbRequiredRepresentation{Roles: []string{"any value"}}}
		assert.False(t, IsAttributeRequired(attrb, frontend))
	})
	t.Run("Roles contains requesterType", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: &kc.ProfileAttrbRequiredRepresentation{Roles: []string{requesterType}}}
		assert.True(t, IsAttributeRequired(attrb, frontend))
	})
}

func TestValidate(t *testing.T) {
	var user getfield
	var realm = "the-realm"
	var ctx = context.TODO()

	t.Run("Can't get user profile", func(t *testing.T) {
		var mup = &mockUserProfile{err: errors.New("any error")}
		assert.NotNil(t, Validate(ctx, mup, realm, &user, "account", true))
	})
	t.Run("Success", func(t *testing.T) {
		var mup = &mockUserProfile{err: nil}
		assert.Nil(t, Validate(ctx, mup, realm, &user, "account", true))
	})
}

func TestValidateUser(t *testing.T) {
	var (
		input = &getfield{returnValue: nil}
	)

	t.Run("Attribute is not required for this frontend type", func(t *testing.T) {
		assert.Nil(t, ValidateUser(createProfile("", nil, "xxx", false), input, frontend, true))
	})

	t.Run("No validator, attribute is not required", func(t *testing.T) {
		assert.Nil(t, ValidateUser(createProfile("", nil, frontend, false), input, frontend, true))
	})
	t.Run("No validator, attribute is required, validation checks mandatory fields", func(t *testing.T) {
		assert.NotNil(t, ValidateUser(createProfile("", nil, frontend, true), input, frontend, true))
	})
	t.Run("No validator, attribute is required, validation does not check mandatory fields", func(t *testing.T) {
		assert.Nil(t, ValidateUser(createProfile("", nil, frontend, true), input, frontend, false))
	})
	t.Run("Validation success", func(t *testing.T) {
		input.returnValue = ptr("value")
		assert.Nil(t, ValidateUser(createProfile("", nil, frontend, true), input, frontend, false))
	})
	t.Run("Validation fails", func(t *testing.T) {
		input.returnValue = ptr("x")
		assert.NotNil(t, ValidateUser(createProfile("", nil, frontend, true), input, frontend, false))
	})
}

func TestValidateAttribute(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{}
		input     = &getfield{returnValue: nil}
	)
	t.Run("No validator", func(t *testing.T) {
		assert.Nil(t, validateAttribute(attribute, input, nil))
	})
	t.Run("Unknown validator", func(t *testing.T) {
		attribute.Validations = kc.ProfileAttrbValidationRepresentation{
			"unknown": kc.ProfileAttrValidatorRepresentation{},
		}
		assert.NotNil(t, validateAttribute(attribute, input, nil))
	})
	t.Run("Validation fails", func(t *testing.T) {
		attribute.Validations = kc.ProfileAttrbValidationRepresentation{
			"length": kc.ProfileAttrValidatorRepresentation{
				"min": 2,
			},
		}
		assert.NotNil(t, validateAttribute(attribute, input, nil))
	})
	t.Run("Validation success", func(t *testing.T) {
		input.returnValue = ptr("xxx")
		assert.NotNil(t, validateAttribute(attribute, input, nil))
	})
}

func TestValidatorEmail(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{}
	)
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeEmail(attribute, validator, time.Now(), nil))
	})
	t.Run("email is valid", func(t *testing.T) {
		assert.Nil(t, validateAttributeEmail(attribute, validator, ptr("name@domain.ch"), nil))
	})
	t.Run("email is invalid", func(t *testing.T) {
		assert.NotNil(t, validateAttributeEmail(attribute, validator, "name#domain.ch", nil))
	})
}

func TestValidatorInteger(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{"min": 5, "max": 20}
	)
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeInteger(attribute, validator, "abc", nil))
	})
	t.Run("too small", func(t *testing.T) {
		assert.NotNil(t, validateAttributeInteger(attribute, validator, int32(0), nil))
	})
	t.Run("too high", func(t *testing.T) {
		assert.NotNil(t, validateAttributeInteger(attribute, validator, "99999", nil))
	})
	t.Run("valid input", func(t *testing.T) {
		assert.Nil(t, validateAttributeInteger(attribute, validator, 12, nil))
	})
}

func TestValidatorDouble(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{"min": 5, "max": 20}
	)
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeDouble(attribute, validator, "abc", nil))
	})
	t.Run("too small", func(t *testing.T) {
		assert.NotNil(t, validateAttributeDouble(attribute, validator, float32(4.1), nil))
	})
	t.Run("too high", func(t *testing.T) {
		assert.NotNil(t, validateAttributeDouble(attribute, validator, float64(99999.9), nil))
	})
	t.Run("valid input", func(t *testing.T) {
		assert.Nil(t, validateAttributeDouble(attribute, validator, int64(12), nil))
	})
}

func TestValidatorLength(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
	)
	t.Run("No min, no max", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{}
		t.Run("input is string pointer", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, ptr("123"), nil))
		})
		t.Run("input is string", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, "123", nil))
		})
		t.Run("input is time", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, time.Now(), nil))
		})
	})
	t.Run("Min length is 5", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{"min": 5}
		t.Run("valid input, value is a string pointer", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, ptr("12345678"), nil))
		})
		t.Run("too short input, value is a string", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, "123", nil))
		})
	})
	t.Run("Min length is 5, Max length is 7", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{"min": "5", "max": 7}
		t.Run("too long input, value is a string pointer", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, ptr("12345678"), nil))
		})
		t.Run("too short input, value is a string", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, "123", nil))
		})
		t.Run("valid input, value is a string", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, "123456", nil))
		})
	})
}

func TestValidatorPattern(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{"pattern": `^\d\w\d$`}
	)
	t.Run("Generic pattern", func(t *testing.T) {
		t.Run("invalid input", func(t *testing.T) {
			assert.NotNil(t, validateAttributePattern(attribute, validator, "abc", nil))
		})
		t.Run("valid, string pointer", func(t *testing.T) {
			assert.Nil(t, validateAttributePattern(attribute, validator, ptr("1a1"), nil))
		})
		t.Run("valid, string", func(t *testing.T) {
			assert.Nil(t, validateAttributePattern(attribute, validator, ptr("2b2"), nil))
		})
		t.Run("invalid input type", func(t *testing.T) {
			assert.NotNil(t, validateAttributePattern(attribute, validator, 12, nil))
		})
	})
	t.Run("URI pattern", func(t *testing.T) {
		t.Run("invalid input", func(t *testing.T) {
			assert.NotNil(t, validateAttributeURI(attribute, validator, "abc", nil))
		})
		t.Run("valid", func(t *testing.T) {
			assert.Nil(t, validateAttributeURI(attribute, validator, ptr("https://elca.ch/path"), nil))
		})
		t.Run("invalid input type", func(t *testing.T) {
			assert.NotNil(t, validateAttributeURI(attribute, validator, 12, nil))
		})
	})
	validator = kc.ProfileAttrValidatorRepresentation{}
	t.Run("Prohibited username characters", func(t *testing.T) {
		t.Run("invalid input", func(t *testing.T) {
			assert.NotNil(t, validateAttributeUsernameProhibitedChars(attribute, validator, `a<b%c`, nil))
		})
		t.Run("valid input", func(t *testing.T) {
			assert.Nil(t, validateAttributeUsernameProhibitedChars(attribute, validator, "abc", nil))
		})
	})
	validator = kc.ProfileAttrValidatorRepresentation{}
	t.Run("Prohibited person name characters", func(t *testing.T) {
		t.Run("invalid input", func(t *testing.T) {
			assert.NotNil(t, validateAttributePersonNameProhibitedChars(attribute, validator, `a<b%c`, nil))
		})
		t.Run("valid input", func(t *testing.T) {
			assert.Nil(t, validateAttributePersonNameProhibitedChars(attribute, validator, "abc", nil))
		})
	})
}

func TestValidatorOptions(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{"options": []interface{}{"one", "two", "tree", "viva", "l'algerie"}}
	)
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeOptions(attribute, validator, time.Now(), nil))
	})
	t.Run("valid, string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeOptions(attribute, validator, ptr("two"), nil))
	})
	t.Run("valid, string", func(t *testing.T) {
		assert.Nil(t, validateAttributeOptions(attribute, validator, "viva", nil))
	})
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeOptions(attribute, validator, "switzerland", nil))
	})
}

func TestValidatorLocalDate(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{}
	)
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeLocalDate(attribute, validator, time.Now(), nil))
	})
	t.Run("valid, string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeLocalDate(attribute, validator, ptr("31.12.2027"), nil))
	})
	t.Run("valid, string", func(t *testing.T) {
		assert.Nil(t, validateAttributeLocalDate(attribute, validator, "29.02.2028", nil))
	})
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeLocalDate(attribute, validator, "29.02.2029", nil))
	})
}

func TestValidatorCtDate(t *testing.T) {
	var (
		nextYear        = time.Now().Year() + 1
		attribute       = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator       = kc.ProfileAttrValidatorRepresentation{}
		inThePast       = "01.01.2001"
		inTheFuture     = fmt.Sprintf("%d-12-31", nextYear)
		timeInThePast   = time.Now().Add(-2400 * time.Hour)
		timeInTheFuture = time.Now().Add(2400 * time.Hour)
	)
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtDate(attribute, validator, time.Hour, nil))
	})
	t.Run("valid, string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtDate(attribute, validator, ptr("2027-12-31"), nil))
	})
	t.Run("valid, string", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtDate(attribute, validator, "29.02.2028", nil))
	})
	t.Run("valid, time.Time pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtDate(attribute, validator, &timeInThePast, nil))
	})
	t.Run("valid, time.Time", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtDate(attribute, validator, timeInThePast, nil))
	})
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtDate(attribute, validator, "29.02.2029", nil))
	})

	t.Run("Validation accepts only dates in the past", func(t *testing.T) {
		validator = kc.ProfileAttrValidatorRepresentation{"past": "true"}
		t.Run("success", func(t *testing.T) {
			assert.Nil(t, validateAttributeCtDate(attribute, validator, inThePast, nil))
		})
		t.Run("success", func(t *testing.T) {
			assert.Nil(t, validateAttributeCtDate(attribute, validator, timeInThePast, nil))
		})
		t.Run("failure", func(t *testing.T) {
			assert.NotNil(t, validateAttributeCtDate(attribute, validator, inTheFuture, nil))
		})
		t.Run("failure", func(t *testing.T) {
			assert.NotNil(t, validateAttributeCtDate(attribute, validator, timeInTheFuture, nil))
		})
	})
	t.Run("Validation accepts only dates in the future", func(t *testing.T) {
		validator = kc.ProfileAttrValidatorRepresentation{"future": "true"}
		t.Run("success", func(t *testing.T) {
			assert.Nil(t, validateAttributeCtDate(attribute, validator, inTheFuture, nil))
		})
		t.Run("success", func(t *testing.T) {
			assert.Nil(t, validateAttributeCtDate(attribute, validator, timeInTheFuture, nil))
		})
		t.Run("failure", func(t *testing.T) {
			assert.NotNil(t, validateAttributeCtDate(attribute, validator, inThePast, nil))
		})
		t.Run("failure", func(t *testing.T) {
			assert.NotNil(t, validateAttributeCtDate(attribute, validator, timeInThePast, nil))
		})
	})
}

func TestValidateAttributeCtMultiRegex(t *testing.T) {
	var attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}

	t.Run("Ensure pattern.go is choosen first", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{"pattern": `^wxc$`}
		var value = "123456"
		assert.NotNil(t, validateAttributeCtMultiRegex(attribute, validator, value, nil))

		validator["pattern.go"] = `^\d+$`
		assert.Nil(t, validateAttributeCtMultiRegex(attribute, validator, value, nil))
	})

	var validator = kc.ProfileAttrValidatorRepresentation{"pattern.go": `^\d{3}$`}
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtMultiRegex(attribute, validator, time.Now(), nil))
	})
	t.Run("Valid string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtMultiRegex(attribute, validator, ptr("123"), nil))
	})
	t.Run("Valid string", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtMultiRegex(attribute, validator, "123", nil))
	})
	t.Run("Invalid string", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtMultiRegex(attribute, validator, "1x3", nil))
	})
}

func TestValidateAttributeCtPhoneNumber(t *testing.T) {
	var attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
	var validator = kc.ProfileAttrValidatorRepresentation{}

	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtPhoneNumber(attribute, validator, time.Now(), nil))
	})
	t.Run("Valid string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtPhoneNumber(attribute, validator, ptr("+41763111122"), nil))
	})
	t.Run("Valid string", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtPhoneNumber(attribute, validator, "+41763111122", nil))
	})
	t.Run("Invalid string", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtPhoneNumber(attribute, validator, "+4176311112", nil))
	})
}

func TestValidateAttributeCtGLN(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockGlnVerifier = mock.NewGlnVerifier(mockCtrl)
	GlnVerifier = mockGlnVerifier

	var attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
	var validator = kc.ProfileAttrValidatorRepresentation{}
	var input = UserRepresentation{
		FirstName: ptr("John"),
		LastName:  ptr("Doe"),
	}

	t.Run("Invalid GLN", func(t *testing.T) {
		mockGlnVerifier.EXPECT().ValidateGLN("John", "Doe", "000").Return(errors.New("invalid GLN"))
		assert.NotNil(t, validateAttributeCtGLN(attribute, validator, "000", input))
	})

	t.Run("Valid GLN", func(t *testing.T) {
		mockGlnVerifier.EXPECT().ValidateGLN("John", "Doe", "7612345000000").Return(nil)
		assert.Nil(t, validateAttributeCtGLN(attribute, validator, "7612345000000", input))
	})

	t.Run("Invalid GLN pointer", func(t *testing.T) {
		mockGlnVerifier.EXPECT().ValidateGLN("John", "Doe", "000").Return(errors.New("invalid GLN"))
		assert.NotNil(t, validateAttributeCtGLN(attribute, validator, ptr("000"), input))
	})

	t.Run("Valid GLN pointer", func(t *testing.T) {
		mockGlnVerifier.EXPECT().ValidateGLN("John", "Doe", "7612345000000").Return(nil)
		assert.Nil(t, validateAttributeCtGLN(attribute, validator, ptr("7612345000000"), input))
	})
}

func TestIfNotNil(t *testing.T) {
	assert.Nil(t, IfNotNil(nil))
	assert.NotNil(t, IfNotNil(ptr("111")))
}

func TestIfTimePtrNotNil(t *testing.T) {
	var now = time.Now()

	assert.Nil(t, IfTimePtrNotNil(nil))
	assert.NotNil(t, IfTimePtrNotNil(&now))
}
