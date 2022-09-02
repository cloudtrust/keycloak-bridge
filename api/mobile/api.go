package mobileapi

import (
	"context"
	"encoding/json"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// UserInformationRepresentation struct
type UserInformationRepresentation struct {
	RealmDisplayName *string                        `json:"realmDisplayName,omitempty"`
	Accreditations   *[]AccreditationRepresentation `json:"accreditations,omitempty"`
	Checks           *[]CheckRepresentation         `json:"checks,omitempty"`
	Actions          *[]string                      `json:"actions,omitempty"`
	PendingActions   *[]string                      `json:"pendingActions,omitempty"`
}

// AccreditationRepresentation is a representation of an accreditation
type AccreditationRepresentation struct {
	Type       *string `json:"type"`
	ExpiryDate *string `json:"expiryDate"`
	Expired    *bool   `json:"expired,omitempty"`
	Revoked    *bool   `json:"revoked,omitempty"`
}

// CheckRepresentation is a representation of a check
type CheckRepresentation struct {
	Type   *string `json:"type"`
	Nature *string `json:"nature"`
	Date   *string `json:"date"`
}

// SetAccreditations sets the user accreditations
func (u *UserInformationRepresentation) SetAccreditations(ctx context.Context, attrAccreditations []string, logger keycloakb.Logger) {
	if len(attrAccreditations) == 0 {
		u.Accreditations = nil
		return
	}

	var accreds []AccreditationRepresentation
	var bFalse = false
	for _, accredJSON := range attrAccreditations {
		var accred AccreditationRepresentation
		if json.Unmarshal([]byte(accredJSON), &accred) == nil {
			accred.Expired = keycloakb.IsDateInThePast(accred.ExpiryDate)
			if accred.Revoked == nil {
				accred.Revoked = &bFalse
			}
			accreds = append(accreds, accred)
		} else {
			logger.Warn(ctx, "msg", "Can't unmarshall JSON", "json", accredJSON)
		}
	}
	u.Accreditations = &accreds
}

// SetChecks sets the user checks
func (u *UserInformationRepresentation) SetChecks(accreditationsChecks []accreditationsclient.CheckRepresentation) {
	if len(accreditationsChecks) == 0 {
		u.Checks = nil
		return
	}

	var checks []CheckRepresentation
	for _, check := range accreditationsChecks {
		var convertedCheck = CheckRepresentation{
			Nature: check.Nature,
			Type:   check.Type,
		}
		if check.DateTime != nil {
			var date = check.DateTime.Format(constants.SupportedDateLayouts[0])
			convertedCheck.Date = &date
		}
		checks = append(checks, convertedCheck)
	}

	u.Checks = &checks
}

// SetActions sets the user actions
func (u *UserInformationRepresentation) SetActions(availableChecks map[string]bool) {
	if len(availableChecks) == 0 {
		u.Actions = nil
		return
	}

	var actions []string
	for checkType, active := range availableChecks {
		if active {
			actions = append(actions, checkType)
		}
	}
	u.Actions = &actions
}
