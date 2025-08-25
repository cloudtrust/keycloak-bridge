package apicommon

import (
	"testing"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func ptr(value string) *string {
	return &value
}

func TestProfileToAPI(t *testing.T) {
	t.Run("Nil content", func(t *testing.T) {
		var profile = kc.UserProfileRepresentation{Attributes: nil, Groups: nil}
		var res = ProfileToAPI(profile, "")
		assert.Nil(t, res.Attributes)
		assert.Nil(t, res.Groups)
	})
	t.Run("Empty arrays", func(t *testing.T) {
		var profile = kc.UserProfileRepresentation{
			Attributes: make([]kc.ProfileAttrbRepresentation, 0),
			Groups:     make([]kc.ProfileGroupRepresentation, 0),
		}
		var res = ProfileToAPI(profile, "")
		assert.NotNil(t, res.Attributes)
		assert.Len(t, res.Attributes, 0)
		assert.NotNil(t, res.Groups)
		assert.Len(t, res.Groups, 0)
	})
}

func TestAttributesToAPI(t *testing.T) {
	t.Run("No attributes", func(t *testing.T) {
		var res = AttributesToAPI(nil, "")
		assert.Nil(t, res)
	})
	t.Run("Two elements", func(t *testing.T) {
		var attrbs = []kc.ProfileAttrbRepresentation{{}, {Name: ptr("dummy")}}
		var res = AttributesToAPI(attrbs, "")
		assert.Len(t, res, len(attrbs))
	})
}

func TestAttributeToAPI(t *testing.T) {
	t.Run("Non-editable element", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Permissions: &kc.ProfileAttrbPermissionsRepresentation{
			Edit: []string{"not-a-user"},
		}}
		var res = AttributeToAPI(attrb, "")
		assert.Nil(t, res)
	})
	t.Run("Non-required element", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: &kc.ProfileAttrbRequiredRepresentation{
			Roles: []string{"not-a-user"},
		}}
		var res = AttributeToAPI(attrb, "")
		assert.False(t, *res.Required)
	})
	t.Run("Required element", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: &kc.ProfileAttrbRequiredRepresentation{
			Roles: []string{"user"},
		}}
		var res = AttributeToAPI(attrb, "")
		assert.True(t, *res.Required)
	})
	t.Run("Not enabled for the given frontend", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{Required: &kc.ProfileAttrbRequiredRepresentation{
			Roles: []string{"user"},
		}}
		var res = AttributeToAPI(attrb, "frontend")
		assert.Nil(t, res)
	})
	t.Run("Read-only element in account API", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{
			Required:    &kc.ProfileAttrbRequiredRepresentation{Roles: []string{"user"}},
			Annotations: map[string]string{"account": "read-only"},
		}
		var res = AttributeToAPI(attrb, "account")
		assert.NotNil(t, res)
		assert.True(t, *res.ReadOnly)
	})
	t.Run("Read-only element in other API", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{
			Required:    &kc.ProfileAttrbRequiredRepresentation{Roles: []string{"user"}},
			Annotations: map[string]string{"frontend": "read-only"},
		}
		var res = AttributeToAPI(attrb, "frontend")
		assert.Nil(t, res)
	})
	t.Run("Enabled for the given frontend", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{
			Required:    &kc.ProfileAttrbRequiredRepresentation{Roles: []string{"user"}},
			Annotations: map[string]string{"frontend": "true"},
		}
		var res = AttributeToAPI(attrb, "frontend")
		assert.NotNil(t, res)
		assert.False(t, *res.ReadOnly)
	})
	t.Run("Attribute is not globally required but required for the given API", func(t *testing.T) {
		var attrb = kc.ProfileAttrbRepresentation{
			Required:    nil,
			Annotations: map[string]string{"frontend": "required"},
		}
		var res = AttributeToAPI(attrb, "frontend")
		assert.NotNil(t, res)
		assert.False(t, *res.ReadOnly)
	})
}

func TestValidationsToAPI(t *testing.T) {
	t.Run("Nil value", func(t *testing.T) {
		assert.Nil(t, ValidationsToAPI(nil))
	})
	t.Run("Three values", func(t *testing.T) {
		var validation = kc.ProfileAttrbValidationRepresentation{}
		validation["one"] = kc.ProfileAttrValidatorRepresentation{}
		validation["two"] = kc.ProfileAttrValidatorRepresentation{}
		validation["three"] = kc.ProfileAttrValidatorRepresentation{}
		var res = ValidationsToAPI(validation)
		assert.Len(t, res, 3)
	})
}

func TestToValidator(t *testing.T) {
	t.Run("Nil value", func(t *testing.T) {
		assert.Nil(t, ToValidator(nil))
	})
	t.Run("Four values", func(t *testing.T) {
		var validator = kc.ProfileAttrValidatorRepresentation{}
		validator["1"] = "a value"
		validator["2"] = nil
		validator["3"] = t
		validator["4"] = 3.14
		var res = ToValidator(validator)
		assert.Len(t, res, 4)
		for k, v := range res {
			assert.Equal(t, validator[k], v)
		}
	})
}

func TestAttributeAnnotationsToAPI(t *testing.T) {
	t.Run("Nil value", func(t *testing.T) {
		assert.Len(t, AttributeAnnotationsToAPI(nil), 0)
	})
	t.Run("Not whitelisted annotations", func(t *testing.T) {
		assert.Len(t, AttributeAnnotationsToAPI(map[string]string{
			"dummy":      "value",
			"account":    "true",
			"kyc":        "true",
			"management": "true",
			"register":   "true",
		}), 0)
	})
	t.Run("Not whitelisted annotations", func(t *testing.T) {
		var res = AttributeAnnotationsToAPI(map[string]string{"values": "value"})
		assert.Len(t, res, 1)
		assert.Equal(t, "value", res["values"])
	})
}

func TestGroupsToAPI(t *testing.T) {
	var grps = []kc.ProfileGroupRepresentation{
		{
			Name:               ptr("name"),
			DisplayHeader:      ptr("display header"),
			DisplayDescription: ptr("display description"),
			Annotations:        map[string]string{"key1": "value1", "key2": "value2"},
		},
		{},
		{},
	}
	var res = GroupsToAPI(grps)
	assert.Len(t, res, len(grps))
	assert.Equal(t, grps[0].Name, res[0].Name)
	assert.Equal(t, grps[0].DisplayHeader, res[0].DisplayHeader)
	assert.Equal(t, grps[0].DisplayDescription, res[0].DisplayDescription)
	assert.Equal(t, grps[0].Annotations, res[0].Annotations)
}
