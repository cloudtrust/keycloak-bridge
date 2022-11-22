package profile

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	kc "github.com/cloudtrust/keycloak-client/v2"
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
		assert.Nil(t, validateAttribute(attribute, input))
	})
	t.Run("Unknown validator", func(t *testing.T) {
		attribute.Validations = kc.ProfileAttrbValidationRepresentation{
			"unknown": kc.ProfileAttrValidatorRepresentation{},
		}
		assert.NotNil(t, validateAttribute(attribute, input))
	})
	t.Run("Validation fails", func(t *testing.T) {
		attribute.Validations = kc.ProfileAttrbValidationRepresentation{
			"length": kc.ProfileAttrValidatorRepresentation{
				"min": 2,
			},
		}
		assert.NotNil(t, validateAttribute(attribute, input))
	})
	t.Run("Validation success", func(t *testing.T) {
		input.returnValue = ptr("xxx")
		assert.NotNil(t, validateAttribute(attribute, input))
	})
}

func TestValidatorEmail(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{}
	)
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeEmail(attribute, validator, time.Now()))
	})
	t.Run("email is valid", func(t *testing.T) {
		assert.Nil(t, validateAttributeEmail(attribute, validator, ptr("name@domain.ch")))
	})
	t.Run("email is invalid", func(t *testing.T) {
		assert.NotNil(t, validateAttributeEmail(attribute, validator, "name#domain.ch"))
	})
}

func TestValidatorInteger(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{"min": 5, "max": 20}
	)
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeInteger(attribute, validator, "abc"))
	})
	t.Run("too small", func(t *testing.T) {
		assert.NotNil(t, validateAttributeInteger(attribute, validator, int32(0)))
	})
	t.Run("too high", func(t *testing.T) {
		assert.NotNil(t, validateAttributeInteger(attribute, validator, "99999"))
	})
	t.Run("valid input", func(t *testing.T) {
		assert.Nil(t, validateAttributeInteger(attribute, validator, 12))
	})
}

func TestValidatorDouble(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{"min": 5, "max": 20}
	)
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeDouble(attribute, validator, "abc"))
	})
	t.Run("too small", func(t *testing.T) {
		assert.NotNil(t, validateAttributeDouble(attribute, validator, float32(4.1)))
	})
	t.Run("too high", func(t *testing.T) {
		assert.NotNil(t, validateAttributeDouble(attribute, validator, float64(99999.9)))
	})
	t.Run("valid input", func(t *testing.T) {
		assert.Nil(t, validateAttributeDouble(attribute, validator, int64(12)))
	})
}

func TestValidatorLength(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
	)
	t.Run("No min, no max", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{}
		t.Run("input is string pointer", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, ptr("123")))
		})
		t.Run("input is string", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, "123"))
		})
		t.Run("input is time", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, time.Now()))
		})
	})
	t.Run("Min length is 5", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{"min": 5}
		t.Run("valid input, value is a string pointer", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, ptr("12345678")))
		})
		t.Run("too short input, value is a string", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, "123"))
		})
	})
	t.Run("Min length is 5, Max length is 7", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{"min": "5", "max": 7}
		t.Run("too long input, value is a string pointer", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, ptr("12345678")))
		})
		t.Run("too short input, value is a string", func(t *testing.T) {
			assert.NotNil(t, validateAttributeLength(attribute, validator, "123"))
		})
		t.Run("valid input, value is a string", func(t *testing.T) {
			assert.Nil(t, validateAttributeLength(attribute, validator, "123456"))
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
			assert.NotNil(t, validateAttributePattern(attribute, validator, "abc"))
		})
		t.Run("valid, string pointer", func(t *testing.T) {
			assert.Nil(t, validateAttributePattern(attribute, validator, ptr("1a1")))
		})
		t.Run("valid, string", func(t *testing.T) {
			assert.Nil(t, validateAttributePattern(attribute, validator, ptr("2b2")))
		})
		t.Run("invalid input type", func(t *testing.T) {
			assert.NotNil(t, validateAttributePattern(attribute, validator, 12))
		})
	})
	t.Run("URI pattern", func(t *testing.T) {
		t.Run("invalid input", func(t *testing.T) {
			assert.NotNil(t, validateAttributeURI(attribute, validator, "abc"))
		})
		t.Run("valid", func(t *testing.T) {
			assert.Nil(t, validateAttributeURI(attribute, validator, ptr("https://elca.ch/path")))
		})
		t.Run("invalid input type", func(t *testing.T) {
			assert.NotNil(t, validateAttributeURI(attribute, validator, 12))
		})
	})
	validator = kc.ProfileAttrValidatorRepresentation{}
	t.Run("Prohibited username characters", func(t *testing.T) {
		t.Run("invalid input", func(t *testing.T) {
			assert.NotNil(t, validateAttributeUsernameProhibitedChars(attribute, validator, `a<b%c`))
		})
		t.Run("valid input", func(t *testing.T) {
			assert.Nil(t, validateAttributeUsernameProhibitedChars(attribute, validator, "abc"))
		})
	})
	validator = kc.ProfileAttrValidatorRepresentation{}
	t.Run("Prohibited person name characters", func(t *testing.T) {
		t.Run("invalid input", func(t *testing.T) {
			assert.NotNil(t, validateAttributePersonNameProhibitedChars(attribute, validator, `a<b%c`))
		})
		t.Run("valid input", func(t *testing.T) {
			assert.Nil(t, validateAttributePersonNameProhibitedChars(attribute, validator, "abc"))
		})
	})
}

func TestValidatorOptions(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{"options": []interface{}{"one", "two", "tree", "viva", "l'algerie"}}
	)
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeOptions(attribute, validator, time.Now()))
	})
	t.Run("valid, string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeOptions(attribute, validator, ptr("two")))
	})
	t.Run("valid, string", func(t *testing.T) {
		assert.Nil(t, validateAttributeOptions(attribute, validator, "viva"))
	})
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeOptions(attribute, validator, "switzerland"))
	})
}

func TestValidatorLocalDate(t *testing.T) {
	var (
		attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator = kc.ProfileAttrValidatorRepresentation{}
	)
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeLocalDate(attribute, validator, time.Now()))
	})
	t.Run("valid, string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeLocalDate(attribute, validator, ptr("31.12.2027")))
	})
	t.Run("valid, string", func(t *testing.T) {
		assert.Nil(t, validateAttributeLocalDate(attribute, validator, "29.02.2028"))
	})
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeLocalDate(attribute, validator, "29.02.2029"))
	})
}

func TestValidatorCtDate(t *testing.T) {
	var (
		nextYear    = time.Now().Year() + 1
		attribute   = kc.ProfileAttrbRepresentation{Name: ptr("name")}
		validator   = kc.ProfileAttrValidatorRepresentation{}
		inThePast   = "01.01.2001"
		inTheFuture = fmt.Sprintf("%d-12-31", nextYear)
	)
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtDate(attribute, validator, time.Now()))
	})
	t.Run("valid, string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtDate(attribute, validator, ptr("2027-12-31")))
	})
	t.Run("valid, string", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtDate(attribute, validator, "29.02.2028"))
	})
	t.Run("invalid input", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtDate(attribute, validator, "29.02.2029"))
	})

	t.Run("Validation accepts only dates in the past", func(t *testing.T) {
		validator = kc.ProfileAttrValidatorRepresentation{"past": "true"}
		t.Run("success", func(t *testing.T) {
			assert.Nil(t, validateAttributeCtDate(attribute, validator, inThePast))
		})
		t.Run("failure", func(t *testing.T) {
			assert.NotNil(t, validateAttributeCtDate(attribute, validator, inTheFuture))
		})
	})
	t.Run("Validation accepts only dates in the future", func(t *testing.T) {
		validator = kc.ProfileAttrValidatorRepresentation{"future": "true"}
		t.Run("success", func(t *testing.T) {
			assert.Nil(t, validateAttributeCtDate(attribute, validator, inTheFuture))
		})
		t.Run("failure", func(t *testing.T) {
			assert.NotNil(t, validateAttributeCtDate(attribute, validator, inThePast))
		})
	})
}

func TestValidateAttributeCtMultiRegex(t *testing.T) {
	var attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}

	t.Run("Ensure pattern.go is choosen first", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{"pattern": `^wxc$`}
		var value = "123456"
		assert.NotNil(t, validateAttributeCtMultiRegex(attribute, validator, value))

		validator["pattern.go"] = `^\d+$`
		assert.Nil(t, validateAttributeCtMultiRegex(attribute, validator, value))
	})

	var validator = kc.ProfileAttrValidatorRepresentation{"pattern.go": `^\d{3}$`}
	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtMultiRegex(attribute, validator, time.Now()))
	})
	t.Run("Valid string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtMultiRegex(attribute, validator, ptr("123")))
	})
	t.Run("Valid string", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtMultiRegex(attribute, validator, "123"))
	})
	t.Run("Invalid string", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtMultiRegex(attribute, validator, "1x3"))
	})
}

func TestValidateAttributeCtPhoneNumber(t *testing.T) {
	var attribute = kc.ProfileAttrbRepresentation{Name: ptr("name")}
	var validator = kc.ProfileAttrValidatorRepresentation{}

	t.Run("invalid input type", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtPhoneNumber(attribute, validator, time.Now()))
	})
	t.Run("Valid string pointer", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtPhoneNumber(attribute, validator, ptr("+41763111122")))
	})
	t.Run("Valid string", func(t *testing.T) {
		assert.Nil(t, validateAttributeCtPhoneNumber(attribute, validator, "+41763111122"))
	})
	t.Run("Invalid string", func(t *testing.T) {
		assert.NotNil(t, validateAttributeCtPhoneNumber(attribute, validator, "+4176311112"))
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
