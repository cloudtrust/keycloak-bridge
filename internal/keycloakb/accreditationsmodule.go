package keycloakb

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/cloudtrust/common-service/configuration"
	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client"
)

var (
	dateLayout = constants.SupportedDateLayouts[0]
)

const (
	// CredsIDNow identifies the condition for IDNow service
	CredsIDNow = configuration.CheckKeyIDNow
	// CredsPhysical identifies the condition for physical identification
	CredsPhysical = configuration.CheckKeyPhysical
)

// AccreditationsModule interface
type AccreditationsModule interface {
	GetUserAndPrepareAccreditations(ctx context.Context, accessToken, realmName, userID, condition string) (kc.UserRepresentation, int, error)
}

// AccredsKeycloakClient is the minimum Keycloak client interface for accreditations
type AccredsKeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
}

// AdminConfigurationDBModule interface
type AdminConfigurationDBModule interface {
	GetAdminConfiguration(context.Context, string) (configuration.RealmAdminConfiguration, error)
}

type accredsModule struct {
	keycloakClient AccredsKeycloakClient
	confDBModule   AdminConfigurationDBModule
	logger         Logger
}

// AccreditationRepresentation is a representation of accreditations
type AccreditationRepresentation struct {
	Type       *string `json:"type,omitempty"`
	ExpiryDate *string `json:"expiryDate,omitempty"`
	Revoked    *bool   `json:"revoked,omitempty"`
}

// IsUpdated checks if there are changes in provided values.
// These values are provided by pair: first one is the new value (or nil if no update is expected) and the second one is the former value
func IsUpdated(values ...*string) bool {
	for i := 0; i < len(values)-1; i += 2 {
		var newValue = values[i]
		var formerValue = values[i+1]
		if newValue != nil && (formerValue == nil || !strings.EqualFold(*newValue, *formerValue)) {
			return true
		}
	}
	return false
}

// RevokeAccreditations revokes active accreditations of the given user
func RevokeAccreditations(kcUser *kc.UserRepresentation) {
	var kcAccreds = kcUser.GetAttribute(constants.AttrbAccreditations)
	if len(kcAccreds) == 0 {
		return
	}
	var newAccreds []string
	for _, accred := range kcAccreds {
		newAccreds = append(newAccreds, revoke(accred))
	}
	kcUser.SetAttribute(constants.AttrbAccreditations, newAccreds)
}

func revoke(accredJSON string) string {
	var accred AccreditationRepresentation
	if err := json.Unmarshal([]byte(accredJSON), &accred); err == nil {
		var today = time.Now()
		if expiry, err := time.Parse(dateLayout, *accred.ExpiryDate); err == nil && today.Before(expiry) {
			var bTrue = true
			accred.Revoked = &bTrue
			var bytes, _ = json.Marshal(accred)
			accredJSON = string(bytes)
		}
	}
	return accredJSON
}

// NewAccreditationsModule creates an accreditations module
func NewAccreditationsModule(keycloakClient AccredsKeycloakClient, confDBModule AdminConfigurationDBModule, logger Logger) AccreditationsModule {
	return &accredsModule{
		keycloakClient: keycloakClient,
		confDBModule:   confDBModule,
		logger:         logger,
	}
}

func (am *accredsModule) GetUserAndPrepareAccreditations(ctx context.Context, accessToken, realmName, userID, condition string) (kc.UserRepresentation, int, error) {
	var kcUser kc.UserRepresentation

	// Gets the realm
	var realm, err = am.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		am.logger.Warn(ctx, "msg", "getKeycloakRealm: can't get realm from KC", "err", err.Error())
		return kcUser, 0, errorhandler.CreateInternalServerError("keycloak")
	}

	// Retrieve admin configuration from configuration DB
	var rac configuration.RealmAdminConfiguration
	rac, err = am.confDBModule.GetAdminConfiguration(ctx, *realm.ID)
	if err != nil {
		am.logger.Warn(ctx, "msg", "CreateAccreditations: can't get admin configuration", "err", err.Error())
		return kcUser, 0, errorhandler.CreateInternalServerError("keycloak")
	}

	// Evaluate accreditations to be created
	var newAccreds []string
	newAccreds, err = am.evaluateAccreditations(ctx, rac.Accreditations, condition)
	if err != nil {
		am.logger.Warn(ctx, "msg", "Can't evaluate accreditations", "err", err.Error())
		return kcUser, 0, err
	}

	// Get the user from Keycloak
	kcUser, err = am.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		am.logger.Warn(ctx, "msg", "CreateAccreditations: can't get Keycloak user", "err", err.Error(), "realm", realmName, "user", userID)
		return kcUser, 0, err
	}

	if len(newAccreds) == 0 {
		return kcUser, 0, errorhandler.CreateInternalServerError("noConfiguredAccreditations")
	}

	// Update attributes in kcUser
	var added = 0
	var kcAccreds = kcUser.GetAttribute(constants.AttrbAccreditations)
	for _, newAccred := range newAccreds {
		if !validation.IsStringInSlice(kcAccreds, newAccred) {
			kcAccreds = append(kcAccreds, newAccred)
			added++
		}
	}
	kcUser.SetAttribute(constants.AttrbAccreditations, kcAccreds)

	return kcUser, added, nil
}

func (am *accredsModule) evaluateAccreditations(ctx context.Context, accreds []configuration.RealmAdminAccreditation, condition string) ([]string, error) {
	var newAccreds []string
	for _, modelAccred := range accreds {
		if modelAccred.Condition == nil || *modelAccred.Condition == condition {
			var expiry, err = am.convertDurationToDate(ctx, *modelAccred.Validity)
			if err != nil {
				return nil, err
			}
			var newAccreditationJSON, _ = json.Marshal(AccreditationRepresentation{
				Type:       modelAccred.Type,
				ExpiryDate: expiry,
			})
			newAccreds = append(newAccreds, string(newAccreditationJSON))
		}
	}
	return newAccreds, nil
}

func (am *accredsModule) convertDurationToDate(ctx context.Context, validity string) (*string, error) {
	var expiryDate, err = validation.AddLargeDurationE(time.Now(), validity)
	if err != nil {
		am.logger.Warn(ctx, "msg", "convertDurationToDate: can't convert duration", "duration", validity, "err", err.Error())
		return nil, errorhandler.CreateInternalServerError("duration-convertion")
	}

	var res = expiryDate.Format(dateLayout)

	return &res, nil
}
