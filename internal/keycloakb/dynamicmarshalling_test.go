package keycloakb

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type UserRepresentation struct {
	Name    string         `json:"name"`
	Email   string         `json:"email"`
	Dynamic map[string]any `json:"-"`
}

type userAlias UserRepresentation

func (u *userAlias) GetDynamicFields() map[string]any {
	return u.Dynamic
}

func (u *userAlias) SetDynamicFields(dynamicFields map[string]any) {
	u.Dynamic = dynamicFields
}

func (u UserRepresentation) MarshalJSON() ([]byte, error) {
	alias := userAlias(u)
	return DynamicallyMarshalJSON(&alias)
}

func (u *UserRepresentation) UnmarshalJSON(data []byte) error {
	return DynamicallyUnmarshalJSON(data, (*userAlias)(u))
}

func TestUnmarshal_KnownFieldsOnly(t *testing.T) {
	input := []byte(`{"name":"Alice","email":"alice@example.com"}`)

	var user UserRepresentation
	err := json.Unmarshal(input, &user)
	assert.Nil(t, err)
	assert.Equal(t, "Alice", user.Name)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Len(t, user.Dynamic, 0)
}

func TestUnmarshal_KnownAndDynamic(t *testing.T) {
	input := []byte(`{"name":"Bob","email":"bob@example.com","extra":"value","admin":true,"score":99}`)
	var user UserRepresentation
	err := json.Unmarshal(input, &user)
	assert.Nil(t, err)
	assert.Equal(t, "Bob", user.Name)
	assert.Equal(t, "bob@example.com", user.Email)

	expected := map[string]any{
		"extra": "value",
		"admin": true,
		"score": float64(99),
	}
	assert.Equal(t, expected, user.Dynamic)
}

func TestMarshal_KnownAndDynamic(t *testing.T) {
	user := UserRepresentation{
		Name:  "Charlie",
		Email: "charlie@example.com",
		Dynamic: map[string]any{
			"role": "admin",
			"age":  42,
		},
	}

	b, err := json.Marshal(user)
	assert.Nil(t, err)

	var m map[string]any
	err = json.Unmarshal(b, &m)
	assert.Nil(t, err)

	expected := map[string]any{
		"name":  "Charlie",
		"email": "charlie@example.com",
		"role":  "admin",
		"age":   float64(42),
	}
	assert.Equal(t, expected, m)
}

func TestRoundTrip(t *testing.T) {
	original := UserRepresentation{
		Name:  "Dana",
		Email: "dana@example.com",
		Dynamic: map[string]any{
			"feature_flag": true,
			"custom_id":    "xyz123",
		},
	}

	data, err := json.Marshal(original)
	assert.Nil(t, err)

	var result UserRepresentation
	err = json.Unmarshal(data, &result)
	assert.Nil(t, err)

	assert.Equal(t, original.Name, result.Name)
	assert.Equal(t, original.Email, result.Email)
	assert.Equal(t, original.Dynamic, result.Dynamic)
}

func TestEmptyDynamicInitialized(t *testing.T) {
	input := []byte(`{"name":"Eve","email":"eve@example.com"}`)

	var user UserRepresentation
	err := json.Unmarshal(input, &user)
	assert.Nil(t, err)
	assert.NotNil(t, user.Dynamic)
	assert.Len(t, user.Dynamic, 0)
}
