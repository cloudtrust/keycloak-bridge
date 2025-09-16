package apicomponent

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	compID           = "b5fd6854-ac8e-415b-8779-d89e6b6de3f4"
	compParentID     = "test-community"
	compProviderID   = "Home-realm discovery settings"
	compProviderType = "org.keycloak.services.ui.extend.UiTabProvider"
	compSubType      = ""
	compConfigName   = "hrdSettings"
)

func ptr(value string) *string {
	return &value
}

func testConfig() map[string][]string {
	return map[string][]string{
		compConfigName: {
			"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.67.0/24\\\"}\",\"key\":\"EXTIDP-12345678-abcd-efgh-ijkl-012345678901\"}]",
		},
	}
}

func testComponent() ComponentRepresentation {
	config := testConfig()
	return ComponentRepresentation{
		Config:       &config,
		ID:           &compID,
		ParentID:     &compParentID,
		ProviderID:   &compProviderID,
		ProviderType: &compProviderType,
		SubType:      &compSubType,
	}
}

func TestValidateComponentRepresentation(t *testing.T) {

	tooLongString := strings.Repeat("x", 256)

	t.Run("valid component", func(t *testing.T) {
		comp := testComponent()

		err := comp.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid id", func(t *testing.T) {
		comp := testComponent()

		comp.ID = ptr("not a valid UUID")

		err := comp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid name", func(t *testing.T) {
		comp := testComponent()

		comp.Name = ptr(tooLongString)

		err := comp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid parentId", func(t *testing.T) {
		comp := testComponent()

		comp.ParentID = ptr("not a valid parent ID")

		err := comp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid providerId", func(t *testing.T) {
		comp := testComponent()

		comp.ProviderID = ptr(tooLongString)

		err := comp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid providerType", func(t *testing.T) {
		comp := testComponent()

		comp.ProviderType = ptr(tooLongString)

		err := comp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid subType", func(t *testing.T) {
		comp := testComponent()

		comp.SubType = ptr(tooLongString)

		err := comp.Validate()
		assert.Error(t, err)
	})

}
