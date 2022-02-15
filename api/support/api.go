package apisupport

import (
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// EmailInfo struct
type EmailInfo struct {
	Realm        *string `json:"realm"`
	CreationDate *int64  `json:"creationDate,omitempty"`
}

func ConvertToEmailInfo(input []kc.EmailInfoRepresentation) []EmailInfo {
	var res []EmailInfo
	for _, nfo := range input {
		res = append(res, EmailInfo{
			Realm:        nfo.RealmName,
			CreationDate: nfo.CreationDate,
		})
	}
	return res
}
