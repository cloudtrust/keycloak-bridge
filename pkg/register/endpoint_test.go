package register

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	logger "github.com/cloudtrust/common-service/v2/log"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

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
		anyError         = errors.New("any error")
		m                = map[string]string{}
		mockProfileCache = mock.NewUserProfileCache(mockCtrl)
		logger           = logger.NewNopLogger()
	)

	t.Run("No specified realm", func(t *testing.T) {
		var bytes, _ = json.Marshal(user)
		m[reqBody] = string(bytes)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm, mockProfileCache, logger)(context.Background(), m)
		assert.NotNil(t, err)
	})
	t.Run("Can't get user profile", func(t *testing.T) {
		m[prmRealm] = realm
		mockProfileCache.EXPECT().GetRealmUserProfile(gomock.Any(), realm).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm, mockProfileCache, logger)(context.Background(), m)
		assert.NotNil(t, err)
	})
	t.Run("Input does not match user profile", func(t *testing.T) {
		var bytes, _ = json.Marshal(user)
		m[prmRealm] = realm
		m[reqBody] = string(bytes)
		mockProfileCache.EXPECT().GetRealmUserProfile(gomock.Any(), realm).Return(kc.UserProfileRepresentation{
			Attributes: []kc.ProfileAttrbRepresentation{
				{
					Name: ptr("firstName"),
					Validations: kc.ProfileAttrbValidationRepresentation{
						"ct-phonenumber": kc.ProfileAttrValidatorRepresentation{},
					},
					Annotations: map[string]string{
						"register": "true",
					},
				},
			},
		}, nil)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm, mockProfileCache, logger)(context.Background(), m)
		assert.NotNil(t, err)
	})
	mockProfileCache.EXPECT().GetRealmUserProfile(gomock.Any(), gomock.Any()).Return(kc.UserProfileRepresentation{}, nil).AnyTimes()

	t.Run("Valid request", func(t *testing.T) {
		var bytes, _ = json.Marshal(apiregister.UserRepresentation{})
		var socialRealm = "realm-123456"
		m[prmRealm] = realm
		m[reqBody] = string(bytes)
		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), socialRealm, realm, gomock.Any(), nil).Return("", nil)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm, mockProfileCache, logger)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("Invalid JSON in body", func(t *testing.T) {
		m[prmRealm] = realm
		m[reqBody] = "{"
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm, mockProfileCache, logger)(context.Background(), m)
		assert.NotNil(t, err)
	})

	t.Run("RegisterCorpUser", func(t *testing.T) {
		m[prmCorpRealm] = socialRealm
		var bytes, _ = json.Marshal(apiregister.UserRepresentation{})
		m[reqBody] = string(bytes)
		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), socialRealm, socialRealm, gomock.Any(), nil).Return("", nil)
		_, err := MakeRegisterCorpUserEndpoint(mockRegisterComponent, mockProfileCache, logger)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("Register with context key", func(t *testing.T) {
		var bytes, _ = json.Marshal(apiregister.UserRepresentation{})
		var socialRealm = "realm-123456"
		var ctxKey = "context-key"
		m[prmRealm] = realm
		m[reqBody] = string(bytes)
		m[prmContextKey] = ctxKey
		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), socialRealm, realm, gomock.Any(), &ctxKey).Return("", nil)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent, socialRealm, mockProfileCache, logger)(context.Background(), m)
		assert.Nil(t, err)
	})
}

func TestMakeGetConfigurationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockRegisterComponent := mock.NewComponent(mockCtrl)

	t.Run("Success", func(t *testing.T) {
		var realm = "my-realm"
		var m = map[string]string{prmRealm: realm}
		mockRegisterComponent.EXPECT().GetConfiguration(gomock.Any(), realm).Return(apiregister.ConfigurationRepresentation{}, nil)
		_, err := MakeGetConfigurationEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}

func TestMakeGetUserProfileEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockRegisterComponent = mock.NewComponent(mockCtrl)

		realm = "my-realm"
		m     = map[string]string{prmRealm: realm}
	)

	t.Run("MakeGetUserProfile", func(t *testing.T) {
		mockRegisterComponent.EXPECT().GetUserProfile(gomock.Any(), gomock.Any()).Return(apicommon.ProfileRepresentation{}, nil)
		_, err := MakeGetUserProfileEndpoint(mockRegisterComponent, realm)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeGetCorpUserProfile", func(t *testing.T) {
		mockRegisterComponent.EXPECT().GetUserProfile(gomock.Any(), gomock.Any()).Return(apicommon.ProfileRepresentation{}, nil)
		_, err := MakeGetCorpUserProfileEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}
