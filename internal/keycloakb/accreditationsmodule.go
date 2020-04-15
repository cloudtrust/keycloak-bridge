package keycloakb

import (
	"context"
	"encoding/json"
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
	for _, modelAccred := range rac.Accreditations {
		if modelAccred.Condition == nil || *modelAccred.Condition == condition {
			var expiry *string
			expiry, err = am.convertDurationToDate(ctx, *modelAccred.Validity)
			if err != nil {
				return kcUser, 0, err
			}
			var newAccreditationJSON, _ = json.Marshal(AccreditationRepresentation{
				Type:       modelAccred.Type,
				ExpiryDate: expiry,
			})
			newAccreds = append(newAccreds, string(newAccreditationJSON))
		}
	}

	// Get the user from Keycloak
	kcUser, err = am.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		am.logger.Warn(ctx, "msg", "CreateAccreditations: can't get Keycloak user", "err", err.Error(), "realm", realmName, "user", userID)
		return kcUser, 0, err
	}

	// Update attributes in kcUser
	// If no new accreditation, return
	var added = 0
	if len(newAccreds) > 0 {
		var kcAccreds = kcUser.GetAttribute(constants.AttrbAccreditations)
		for _, newAccred := range newAccreds {
			if !validation.IsStringInSlice(kcAccreds, newAccred) {
				kcAccreds = append(kcAccreds, newAccred)
				added++
			}
		}
		kcUser.SetAttribute(constants.AttrbAccreditations, kcAccreds)
	}

	return kcUser, added, nil
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
