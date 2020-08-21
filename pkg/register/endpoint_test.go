package register

import (
	"context"
	"encoding/json"
	"testing"

	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func ptr(value string) *string {
	return &value
}

func TestMakeRegisterUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockRegisterComponent := mock.NewComponent(mockCtrl)

	var (
		realm       = "my-realm"
		socialRealm = "social-realm"
		user        = apiregister.UserRepresentation{
			FirstName:            ptr("John"),
			LastName:             ptr("Doe"),
			Gender:               ptr("M"),
			Email:                ptr("email@domain.com"),
			PhoneNumber:          ptr("+41220123456"),
			BirthDate:            ptr("20.12.2012"),
			BirthLocation:        ptr("Bern"),
			Nationality:          ptr("CH"),
			IDDocumentType:       ptr("PASSPORT"),
			IDDocumentNumber:     ptr("012345678901234"),
			IDDocumentExpiration: ptr("31.12.2059"),
			IDDocumentCountry:    ptr("CH"),
			Locale:               ptr("fr"),
		}
		m = map[string]string{}
	)

	t.Run("No specified realm", func(t *testing.T) {
		var bytes, _ = json.Marshal(user)
		m[prmRealm] = ""
		m[reqBody] = string(bytes)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, realm)(context.Background(), m)
		assert.NotNil(t, err)
	})

	t.Run("Valid request", func(t *testing.T) {
		var bytes, _ = json.Marshal(user)
		var socialRealm = "realm-123456"
		m[prmRealm] = realm
		m[reqBody] = string(bytes)
		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), socialRealm, realm, user).Return("", nil).Times(1)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("Invalid JSON in body", func(t *testing.T) {
		m[prmRealm] = realm
		m[reqBody] = "{"
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm)(context.Background(), m)
		assert.NotNil(t, err)
	})
	t.Run("Missing mandatory fields", func(t *testing.T) {
		m[prmRealm] = realm
		m[reqBody] = "{}"
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm)(context.Background(), m)
		assert.NotNil(t, err)
	})

	t.Run("RegisterCorpUser", func(t *testing.T) {
		m[prmCorpRealm] = socialRealm
		var bytes, _ = json.Marshal(user)
		m[reqBody] = string(bytes)
		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), socialRealm, socialRealm, user).Return("", nil).Times(1)
		_, err := MakeRegisterCorpUserEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}

func TestMakeGetConfigurationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockRegisterComponent := mock.NewComponent(mockCtrl)

	t.Run("Missing realm", func(t *testing.T) {
		var m = map[string]string{}
		_, err := MakeGetConfigurationEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		var realm = "my-realm"
		var m = map[string]string{prmRealm: realm}
		mockRegisterComponent.EXPECT().GetConfiguration(gomock.Any(), realm).Return(apiregister.ConfigurationRepresentation{}, nil).Times(1)
		_, err := MakeGetConfigurationEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}
