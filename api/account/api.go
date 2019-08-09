package account_api

import (
	kc "github.com/cloudtrust/keycloak-client"
)

// CredentialRepresentation struct
type CredentialRepresentation struct {
	Id        *string `json:"id,omitempty"`
	Type      *string `json:"type,omitempty"`
	UserLabel *string `json:"userLabel,omitempty"`
}

// ConvertCredential creates an API credential from a KC credential
func ConvertCredential(credKc *kc.CredentialRepresentation) CredentialRepresentation {
	var cred CredentialRepresentation
	cred.Id = credKc.Id
	cred.Type = credKc.Type
	//cred.UserLabel = credKc.UserLabel

	return cred
}

// Regular expressions for parameters validation
const (
	RegExpID = `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`
)
