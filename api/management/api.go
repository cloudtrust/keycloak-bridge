package management_api

import (
	kc "github.com/cloudtrust/keycloak-client"
)

type UserRepresentation struct {
	Id            *string `json:"id,omitempty"`
	Username      *string `json:"username,omitempty"`
	Email         *string `json:"email,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
	EmailVerified *bool   `json:"emailVerified,omitempty"`
	FirstName     *string `json:"firstName,omitempty"`
	LastName      *string `json:"lastName,omitempty"`
	MobilePhone   *string `json:"mobilePhone,omitempty"`
	Label         *string `json:"label,omitempty"`
	Gender        *string `json:"gender,omitempty"`
	BirthDate     *string `json:"birthDate,omitempty"`
	Groups         *[]string `json:"group,omitempty"`
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

type PasswordRepresentation struct {
	Value *string `json:"value,omitempty"`
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
