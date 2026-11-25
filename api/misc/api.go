package apimisc

import (
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// EmailInfo struct
type EmailInfo struct {
	Realm        *string `json:"realm"`
	CreationDate *int64  `json:"creationDate,omitempty"`
}

// ConvertToEmailInfo converts an email information
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

// CircuitBreakerStatus struct
type CircuitBreakerStatus struct {
	Status    *string `json:"status,omitempty"`
	Trigger   *string `json:"trigger,omitempty"`
	Since     *string `json:"since,omitempty"`
	UpdatedBy *string `json:"updatedBy,omitempty"`
}

func ConvertToCircuitBreakerStatus(input kc.CircuitBreakerRepresentation) CircuitBreakerStatus {
	return CircuitBreakerStatus{
		Status:    input.Status,
		Trigger:   input.Trigger,
		Since:     input.Since,
		UpdatedBy: input.UpdatedBy,
	}
}
