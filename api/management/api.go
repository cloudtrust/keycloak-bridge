package management_api

import (
	"strconv"

	kc "github.com/cloudtrust/keycloak-client"
)

type UserRepresentation struct {
	Id                  *string   `json:"id,omitempty"`
	Username            *string   `json:"username,omitempty"`
	Email               *string   `json:"email,omitempty"`
	Enabled             *bool     `json:"enabled,omitempty"`
	EmailVerified       *bool     `json:"emailVerified,omitempty"`
	PhoneNumberVerified *bool     `json:"phoneNumberVerified,omitempty"`
	FirstName           *string   `json:"firstName,omitempty"`
	LastName            *string   `json:"lastName,omitempty"`
	PhoneNumber         *string   `json:"phoneNumber,omitempty"`
	Label               *string   `json:"label,omitempty"`
	Gender              *string   `json:"gender,omitempty"`
	BirthDate           *string   `json:"birthDate,omitempty"`
	CreatedTimestamp    *int64    `json:"createdTimestamp,omitempty"`
	Groups              *[]string `json:"groups,omitempty"`
	Roles               *[]string `json:"roles,omitempty"`
}

type RealmRepresentation struct {
	Id              *string `json:"id,omitempty"`
	KeycloakVersion *string `json:"keycloakVersion,omitempty"`
	Realm           *string `json:"realm,omitempty"`
	DisplayName     *string `json:"displayName,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

type ClientRepresentation struct {
	Id          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
	BaseUrl     *string `json:"baseUrl,omitempty"`
	ClientId    *string `json:"clientId,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

type CredentialRepresentation struct {
	Id          *string              `json:"id,omitempty"`
	Type        *string              `json:"type,omitempty"`
	Algorithm   *string              `json:"algorithm,omitempty"`
	CreatedDate *int64               `json:"createdDate,omitempty"`
	Config      *map[string][]string `json:"config,omitempty"`
}

type RoleRepresentation struct {
	ClientRole  *bool   `json:"clientRole,omitempty"`
	Composite   *bool   `json:"composite,omitempty"`
	ContainerId *string `json:"containerId,omitempty"`
	Description *string `json:"description,omitempty"`
	Id          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
}

type GroupRepresentation struct {
	Id          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
}

type PasswordRepresentation struct {
	Value *string `json:"value,omitempty"`
}

type RealmCustomConfiguration struct {
	DefaultClientId    *string `json:"default_client_id,omitempty"`
	DefaultRedirectUri *string `json:"default_redirect_uri,omitempty"`
}

// ConvertCredential creates an API credential from a KC credential
func ConvertCredential(credKc *kc.CredentialRepresentation) CredentialRepresentation {
	var cred CredentialRepresentation
	cred.Id = credKc.Id
	cred.Type = credKc.Type
	cred.Algorithm = credKc.Algorithm
	cred.CreatedDate = credKc.CreatedDate
	if credKc.Config != nil {
		var m map[string][]string
		m = make(map[string][]string)
		for _, key := range []string{"deviceInfo_Manufacturer", "deviceInfo_Model", "deviceInfo_Name", "deviceInfo_Plateform"} {
			value, ok := (*credKc.Config)[key]
			if ok {
				m[key] = value
			}
		}
		cred.Config = &m
	}
	return cred
}

// ConvertToAPIUser creates an API user representation from  a KC user representation
func ConvertToAPIUser(userKc kc.UserRepresentation) UserRepresentation {
	var userRep UserRepresentation

	userRep.Id = userKc.Id
	userRep.Username = userKc.Username
	userRep.Email = userKc.Email
	userRep.Enabled = userKc.Enabled
	userRep.EmailVerified = userKc.EmailVerified
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName
	userRep.CreatedTimestamp = userKc.CreatedTimestamp

	if userKc.Attributes != nil {
		var m = *userKc.Attributes

		if m["phoneNumber"] != nil {
			var phoneNumber = m["phoneNumber"][0]
			userRep.PhoneNumber = &phoneNumber
		}

		if m["label"] != nil {
			var label = m["label"][0]
			userRep.Label = &label
		}

		if m["gender"] != nil {
			var gender = m["gender"][0]
			userRep.Gender = &gender
		}

		if m["birthDate"] != nil {
			var birthDate = m["birthDate"][0]
			userRep.BirthDate = &birthDate
		}

		if m["phoneNumberVerified"] != nil {
			var phoneNumberVerified, _ = strconv.ParseBool(m["phoneNumberVerified"][0])
			userRep.PhoneNumberVerified = &phoneNumberVerified
		}
	}
	return userRep
}

// ConvertToKCUser creates a KC user representation from an API user
func ConvertToKCUser(user UserRepresentation) kc.UserRepresentation {
	var userRep kc.UserRepresentation

	userRep.Username = user.Username
	userRep.Email = user.Email
	userRep.Enabled = user.Enabled
	userRep.EmailVerified = user.EmailVerified
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName

	var attributes = make(map[string][]string)

	if user.PhoneNumber != nil {
		attributes["phoneNumber"] = []string{*user.PhoneNumber}
	}

	if user.Label != nil {
		attributes["label"] = []string{*user.Label}
	}

	if user.Gender != nil {
		attributes["gender"] = []string{*user.Gender}
	}

	if user.BirthDate != nil {
		attributes["birthDate"] = []string{*user.BirthDate}
	}

	if user.PhoneNumberVerified != nil {
		attributes["phoneNumberVerified"] = []string{strconv.FormatBool(*user.PhoneNumberVerified)}
	}

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	return userRep
}
