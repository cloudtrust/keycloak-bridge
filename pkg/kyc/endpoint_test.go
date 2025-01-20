package kyc

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const socialRealmName = "socialRealm"

func TestMakeGetActionsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var m = map[string]string{}
	var expectedError = errors.New("get-actions")

	t.Run("GetActions - success case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetActions(gomock.Any()).Return([]apikyc.ActionRepresentation{}, nil)
		_, err := MakeGetActionsEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("GetActions - failure case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetActions(gomock.Any()).Return([]apikyc.ActionRepresentation{}, expectedError)
		_, err := MakeGetActionsEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Equal(t, expectedError, err)
	})
}

func TestGetRealmUserProfileEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var m = map[string]string{}
	var expectedError = errors.New("get-actions")

	t.Run("Corp", func(t *testing.T) {
		t.Run("Success case", func(t *testing.T) {
			mockKYCComponent.EXPECT().GetUserProfile(gomock.Any(), gomock.Any()).Return(apicommon.ProfileRepresentation{}, nil)
			_, err := MakeGetUserProfileEndpoint(mockKYCComponent)(context.Background(), m)
			assert.Nil(t, err)
		})
		t.Run("Failure case", func(t *testing.T) {
			mockKYCComponent.EXPECT().GetUserProfile(gomock.Any(), gomock.Any()).Return(apicommon.ProfileRepresentation{}, expectedError)
			_, err := MakeGetUserProfileEndpoint(mockKYCComponent)(context.Background(), m)
			assert.Equal(t, expectedError, err)
		})
	})

	t.Run("Social", func(t *testing.T) {
		t.Run("Success case", func(t *testing.T) {
			mockKYCComponent.EXPECT().GetUserProfileInSocialRealm(gomock.Any()).Return(apicommon.ProfileRepresentation{}, nil)
			_, err := MakeGetUserProfileInSocialRealmEndpoint(mockKYCComponent)(context.Background(), m)
			assert.Nil(t, err)
		})
		t.Run("Failure case", func(t *testing.T) {
			mockKYCComponent.EXPECT().GetUserProfileInSocialRealm(gomock.Any()).Return(apicommon.ProfileRepresentation{}, expectedError)
			_, err := MakeGetUserProfileInSocialRealmEndpoint(mockKYCComponent)(context.Background(), m)
			assert.Equal(t, expectedError, err)
		})
	})
}

func TestMakeGetUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var userID = "user1234"
	var consentCode = "123456"
	var m = map[string]string{prmUserID: userID}
	var paramsWithConsentCode = map[string]string{prmUserID: userID, prmQryConsent: consentCode}
	var expectedError = errors.New("get-user")

	t.Run("Social - success case without consent code", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserInSocialRealm(gomock.Any(), userID, nil).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserInSocialRealmEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("Social - success case with consent code", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserInSocialRealm(gomock.Any(), userID, &consentCode).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserInSocialRealmEndpoint(mockKYCComponent)(context.Background(), paramsWithConsentCode)
		assert.Nil(t, err)
	})
	t.Run("Social - failure case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserInSocialRealm(gomock.Any(), userID, nil).Return(apikyc.UserRepresentation{}, expectedError)
		_, err := MakeGetUserInSocialRealmEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Equal(t, expectedError, err)
	})

	var realm = "my-realm"

	t.Run("Corporate - success case without consent code", func(t *testing.T) {
		m[prmRealm] = realm
		mockKYCComponent.EXPECT().GetUser(gomock.Any(), realm, userID, nil).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("Corporate - success case with consent code", func(t *testing.T) {
		paramsWithConsentCode[prmRealm] = realm
		mockKYCComponent.EXPECT().GetUser(gomock.Any(), realm, userID, &consentCode).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserEndpoint(mockKYCComponent)(context.Background(), paramsWithConsentCode)
		assert.Nil(t, err)
	})
}

func TestMakeGetUserByUsernameEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var username = "user1234"
	var m = map[string]string{prmQryUserName: username}
	var expectedError = errors.New("get-user")

	t.Run("Social - success case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserByUsernameInSocialRealm(gomock.Any(), username).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserByUsernameInSocialRealmEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("Social - failure case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserByUsernameInSocialRealm(gomock.Any(), username).Return(apikyc.UserRepresentation{}, expectedError)
		_, err := MakeGetUserByUsernameInSocialRealmEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Equal(t, expectedError, err)
	})

	var realm = "my-realm"
	m[prmRealm] = realm

	t.Run("Corporate - success case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserByUsername(gomock.Any(), realm, username).Return(apikyc.UserRepresentation{}, nil)
		_, err := MakeGetUserByUsernameEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("Corporate - failure case", func(t *testing.T) {
		mockKYCComponent.EXPECT().GetUserByUsername(gomock.Any(), realm, username).Return(apikyc.UserRepresentation{}, expectedError)
		_, err := MakeGetUserByUsernameEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Equal(t, expectedError, err)
	})
}

func TestMakeValidateUserInSocialRealmEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockKYCComponent = mock.NewComponent(mockCtrl)
		mockProfileCache = mock.NewUserProfileCache(mockCtrl)
		logger           = log.NewNopLogger()
		endpoint         = MakeValidateUserInSocialRealmEndpoint(mockKYCComponent, mockProfileCache, socialRealmName, logger)

		userID      = "ux467913"
		consentCode = "987654"
		realm       = "the-realm"
		m           = map[string]string{prmUserID: userID}
		ctx         = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		anyError    = errors.New("any")
	)

	t.Run("Input is not a JSON value", func(t *testing.T) {
		m[reqBody] = "{"
		_, err := endpoint(ctx, m)
		assert.NotNil(t, err)
	})
	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		m[reqBody] = `{}`
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, socialRealmName).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := endpoint(ctx, m)
		assert.NotNil(t, err)
	})

	mockProfileCache.EXPECT().GetRealmUserProfile(ctx, socialRealmName).Return(kc.UserProfileRepresentation{}, nil).AnyTimes()

	t.Run("Success case without consent code", func(t *testing.T) {
		m[reqBody] = `{}`
		mockKYCComponent.EXPECT().ValidateUserInSocialRealm(gomock.Any(), userID, gomock.Any(), nil).Return(nil)
		_, err := endpoint(ctx, m)
		assert.Nil(t, err)
	})
	t.Run("ValidateUserInSocialRealm - success case with", func(t *testing.T) {
		m[reqBody] = `{}`
		m[prmQryConsent] = consentCode
		mockKYCComponent.EXPECT().ValidateUserInSocialRealm(gomock.Any(), userID, gomock.Any(), &consentCode).Return(nil)
		_, err := endpoint(ctx, m)
		assert.Nil(t, err)
	})
}

func TestMakeValidateUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockKYCComponent = mock.NewComponent(mockCtrl)
		mockProfileCache = mock.NewUserProfileCache(mockCtrl)
		logger           = log.NewNopLogger()
		endpoint         = MakeValidateUserEndpoint(mockKYCComponent, mockProfileCache, logger)

		realmName = "the-realm"
		userID    = "ux467913"
		m         = map[string]string{prmRealm: realmName, prmUserID: userID}
		ctx       = context.WithValue(context.TODO(), cs.CtContextRealm, realmName)
		anyError  = errors.New("any")
	)

	t.Run("ValidateUser - failure case", func(t *testing.T) {
		m[reqBody] = "{"
		_, err := endpoint(ctx, m)
		assert.NotNil(t, err)
	})
	m[reqBody] = `{}`
	t.Run("GetRealmUserProfile fails", func(t *testing.T) {
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realmName).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := endpoint(ctx, m)
		assert.NotNil(t, err)
	})
	t.Run("Success without consent code", func(t *testing.T) {
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realmName).Return(kc.UserProfileRepresentation{}, nil)
		mockKYCComponent.EXPECT().ValidateUser(gomock.Any(), realmName, userID, gomock.Any(), nil).Return(nil)
		_, err := endpoint(ctx, m)
		assert.Nil(t, err)
	})
	t.Run("Success with consent code", func(t *testing.T) {
		var consent = "123456"
		m[prmQryConsent] = consent
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realmName).Return(kc.UserProfileRepresentation{}, nil)
		mockKYCComponent.EXPECT().ValidateUser(gomock.Any(), realmName, userID, gomock.Any(), &consent).Return(nil)
		_, err := endpoint(ctx, m)
		assert.Nil(t, err)
	})
}

func TestMakeSendSmsConsentCodeEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKYCComponent := mock.NewComponent(mockCtrl)

	var userID = "ux467913"
	var m = map[string]string{prmUserID: userID}

	t.Run("Social", func(t *testing.T) {
		mockKYCComponent.EXPECT().SendSmsConsentCodeInSocialRealm(gomock.Any(), userID).Return(nil)
		_, err := MakeSendSmsConsentCodeInSocialRealmEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("Corporate", func(t *testing.T) {
		var realm = "my-realm"
		m[prmRealm] = realm
		mockKYCComponent.EXPECT().SendSmsConsentCode(gomock.Any(), realm, userID).Return(nil)
		_, err := MakeSendSmsConsentCodeEndpoint(mockKYCComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}

func createValidUser() apikyc.UserRepresentation {
	var (
		gender        = "M"
		firstName     = "Marc"
		lastName      = "El-Bichoun"
		email         = "marcel.bichon@elca.ch"
		phoneNumber   = "+33686550011"
		birthDate     = "31.03.2001"
		birthLocation = "Montreux"
		nationality   = "CH"
		docType       = "ID_CARD"
		docNumber     = "MEL123789654ABC"
		docExp        = "28.02.2050"
		docCountry    = "CH"
	)

	return apikyc.UserRepresentation{
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		Email:                &email,
		PhoneNumber:          &phoneNumber,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		Nationality:          &nationality,
		IDDocumentType:       &docType,
		IDDocumentNumber:     &docNumber,
		IDDocumentExpiration: &docExp,
		IDDocumentCountry:    &docCountry,
		Attachments:          nil,
	}
}

func TestMakeSendSmsCodeEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmUserID] = userID

	var mockKYCComponent = mock.NewComponent(mockCtrl)

	t.Run("Social", func(t *testing.T) {
		mockKYCComponent.EXPECT().SendSmsCodeInSocialRealm(ctx, userID).Return("1234", nil)

		var res, err = MakeSendSmsCodeInSocialRealmEndpoint(mockKYCComponent)(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, map[string]string{"code": "1234"}, res)
	})
	t.Run("Corporate", func(t *testing.T) {
		var realm = "my-realm"
		req[prmRealm] = realm
		mockKYCComponent.EXPECT().SendSmsCode(ctx, realm, userID).Return("1234", nil)

		var res, err = MakeSendSmsCodeEndpoint(mockKYCComponent)(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, map[string]string{"code": "1234"}, res)
	})
}
