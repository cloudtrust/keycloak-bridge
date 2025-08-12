package validation

import (
	"context"
	"net/http"
	"time"

	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/events"
	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
}

// TokenProvider is the interface to retrieve accessToken to access KC
type TokenProvider interface {
	ProvideTokenForRealm(ctx context.Context, realm string) (string, error)
}

// ArchiveDBModule is the interface from the archive module
type ArchiveDBModule interface {
	StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error
}

// EventsReporterModule is the interface of the audit events module
type EventsReporterModule interface {
	ReportEvent(ctx context.Context, event events.Event)
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	GetAdminConfiguration(context.Context, string) (configuration.RealmAdminConfiguration, error)
}

// AccreditationsServiceClient interface
type AccreditationsServiceClient interface {
	NotifyUpdate(ctx context.Context, updateNotifyRequest accreditationsclient.UpdateNotificationRepresentation) ([]string, error)
}

// Component is the register component interface.
type Component interface {
	GetUser(ctx context.Context, realmName string, userID string) (api.UserRepresentation, error)
	UpdateUser(ctx context.Context, realmName string, userID string, user api.UserRepresentation, txnID *string) error
	UpdateUserAccreditations(ctx context.Context, realmName string, userID string, userAccreds []api.AccreditationRepresentation) error
	GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error)
}

// Component is the management component.
type component struct {
	keycloakClient       KeycloakClient
	tokenProvider        TokenProvider
	archiveDBModule      ArchiveDBModule
	eventReporterModule  EventsReporterModule
	accredsService       AccreditationsServiceClient
	configDBModule       ConfigurationDBModule
	logger               log.Logger
	originEvent          string
	unknownAgentRealm    string
	unknownAgentUserID   string
	unknownAgentUsername string
}

// NewComponent returns the management component.
func NewComponent(keycloakClient KeycloakClient, tokenProvider TokenProvider, archiveDBModule ArchiveDBModule, eventReporterModule EventsReporterModule, accredsService AccreditationsServiceClient, configDBModule ConfigurationDBModule, logger log.Logger) Component {
	return &component{
		keycloakClient:       keycloakClient,
		tokenProvider:        tokenProvider,
		archiveDBModule:      archiveDBModule,
		eventReporterModule:  eventReporterModule,
		accredsService:       accredsService,
		configDBModule:       configDBModule,
		logger:               logger,
		originEvent:          "back-office",
		unknownAgentRealm:    "N/A",
		unknownAgentUserID:   "N/A",
		unknownAgentUsername: "N/A",
	}
}

func (c *component) getKeycloakUser(ctx context.Context, realmName string, userID string) (kc.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "getKeycloakUser: can't get accessToken for technical user", "err", err.Error())
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}

	kcUser, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "getKeycloakUser: can't find user in Keycloak", "err", err.Error(), "realmName", realmName, "userID", userID)
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	return kcUser, nil
}

func (c *component) GetUser(ctx context.Context, realmName string, userID string) (api.UserRepresentation, error) {
	var kcUser, err = c.getKeycloakUser(ctx, realmName, userID)
	if err != nil {
		return api.UserRepresentation{}, err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	if adminConfiguration, err := c.configDBModule.GetAdminConfiguration(ctx, realmName); err != nil {
		return api.UserRepresentation{}, err
	} else if adminConfiguration.ShowGlnEditing != nil && *adminConfiguration.ShowGlnEditing {
		if gln := kcUser.GetAttributeString(constants.AttrbBusinessID); gln == nil {
			return api.UserRepresentation{}, errorhandler.CreateBadRequestError("missing.gln")
		}
	}

	var res = api.UserRepresentation{}
	res.ImportFromKeycloak(kcUser)
	return res, nil
}

func (c *component) UpdateUser(ctx context.Context, realmName string, userID string, user api.UserRepresentation, txnID *string) error {
	var validationCtx = &validationContext{
		ctx:       ctx,
		realmName: realmName,
		userID:    userID,
	}

	var kcUpdate = needKcProcessing(user)
	var fc = fields.NewFieldsComparator()

	if kcUpdate || fc.IsAnyFieldUpdated() {
		kcUser, err := c.prepareUpdateUserKeycloak(validationCtx, user, fc)
		if err != nil {
			return err
		}

		err = c.notifyUpdate(validationCtx, kcUser, fc)
		if err != nil {
			return err
		}

		err = c.updateKeycloakUser(validationCtx)
		if err != nil {
			return err
		}
		var username = c.findFirstNonNil(events.CtEventUnknownUsername, user.Username, kcUser.Username)
		// store the API call into the DB
		var details map[string]string
		if txnID != nil {
			details = map[string]string{"txn_id": *txnID}
		}
		c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUser(c.originEvent, "VALIDATION_UPDATE_USER",
			c.unknownAgentRealm, c.unknownAgentUserID, c.unknownAgentUsername,
			realmName, userID, username, details))

		// archive user
		c.archiveUser(validationCtx)
	}

	return nil
}

func (c *component) findFirstNonNil(defaultValue string, values ...*string) string {
	for _, value := range values {
		if value != nil {
			return *value
		}
	}
	return defaultValue
}

func (c *component) UpdateUserAccreditations(ctx context.Context, realmName string, userID string, userAccreds []api.AccreditationRepresentation) error {
	var accessToken, err = c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get accessToken for technical user", "err", err.Error())
		return errorhandler.CreateInternalServerError("keycloak")
	}
	var kcUser kc.UserRepresentation
	kcUser, err = c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to request user to Keycloak", "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	var accreditations keycloakb.AccreditationsProcessor
	var newAccreds []keycloakb.AccreditationRepresentation
	accreditations, err = keycloakb.NewAccreditationsProcessor(kcUser.GetFieldValues(fields.Accreditations))
	creationDate := time.Now().UTC()
	for _, userAccred := range userAccreds {
		newAccreds = append(newAccreds, accreditations.AddAccreditation(creationDate, *userAccred.Name, *userAccred.Validity))
	}

	kcUser.SetFieldValues(fields.Accreditations, accreditations.ToKeycloak())
	err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update Keycloak user", "err", err.Error())
		return err
	}

	var username = c.findFirstNonNil(events.CtEventUnknownUsername, kcUser.Username)
	for _, accred := range newAccreds {
		c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUser(c.originEvent, "ACCREDITATION_GRANTED",
			c.unknownAgentRealm, c.unknownAgentUserID, c.unknownAgentUsername,
			realmName, userID, username, accred.ToDetails()))
	}

	return nil
}

func (c *component) prepareUpdateUserKeycloak(validationCtx *validationContext, user api.UserRepresentation, fc fields.FieldsComparator) (*kc.UserRepresentation, error) {
	var kcUser, err = c.loadKeycloakUserCtx(validationCtx)
	if err != nil {
		return nil, err
	}
	keycloakb.ConvertLegacyAttribute(kcUser)
	_ = user.UpdateFieldsComparatorWithKCFields(fc, kcUser)

	user.ExportToKeycloak(kcUser)
	return kcUser, nil
}

func (c *component) notifyUpdate(validationCtx *validationContext, kcUser *kc.UserRepresentation, fc fields.FieldsComparator) error {
	var currAccreds = kcUser.GetFieldValues(fields.Accreditations)
	var ap, _ = keycloakb.NewAccreditationsProcessor(currAccreds)
	// Shall we revoke some accreditations (if some active accreditation exists)
	if fc.IsAnyFieldUpdated() && len(currAccreds) > 0 && ap.HasActiveAccreditations() {
		var notifyUpdate = accreditationsclient.UpdateNotificationRepresentation{
			UserID:        &validationCtx.userID,
			RealmName:     &validationCtx.realmName,
			UpdatedFields: fc.UpdatedFields(),
		}
		revokeAccreds, err := c.accredsService.NotifyUpdate(validationCtx.ctx, notifyUpdate)
		if err != nil {
			c.logger.Warn(validationCtx.ctx, "msg", "Could not notify accreds service of updated fields", "uid", validationCtx.userID, "fields", notifyUpdate.UpdatedFields)
			return err
		}
		var username = c.findFirstNonNil(events.CtEventUnknownUsername, kcUser.Username)
		ap.RevokeTypes(revokeAccreds, func(accred keycloakb.AccreditationRepresentation) {
			c.eventReporterModule.ReportEvent(validationCtx.ctx, events.NewEventOnUser(c.originEvent, "ACCREDITATION_REVOKED",
				c.unknownAgentRealm, c.unknownAgentUserID, c.unknownAgentUsername,
				validationCtx.realmName, validationCtx.userID, username, accred.ToDetails()))
		})
		validationCtx.kcUser.SetFieldValues(fields.Accreditations, ap.ToKeycloak())
	}
	return nil
}

func needKcProcessing(user api.UserRepresentation) bool {
	var kcUserAttrs = []*string{
		user.Gender,
		user.FirstName,
		user.LastName,
		user.Email,
		user.PhoneNumber,
		user.BirthLocation,
		user.Nationality,
		user.IDDocumentNumber,
		user.IDDocumentType,
		user.IDDocumentCountry,
	}

	for _, attr := range kcUserAttrs {
		if attr != nil {
			return true
		}
	}

	return user.BirthDate != nil || user.IDDocumentExpiration != nil
}

func (c *component) getAccessToken(v *validationContext) (string, error) {
	if v.accessToken == nil {
		if accessToken, err := c.tokenProvider.ProvideTokenForRealm(v.ctx, v.realmName); err == nil {
			v.accessToken = &accessToken
		} else {
			c.logger.Warn(v.ctx, "msg", "Can't get access token", "err", err.Error(), "realm", v.realmName, "user", v.userID)
			return "", err
		}
	}
	return *v.accessToken, nil
}

type validationContext struct {
	ctx         context.Context
	accessToken *string
	realmName   string
	userID      string
	kcUser      *kc.UserRepresentation
}

func (c *component) loadKeycloakUserCtx(v *validationContext) (*kc.UserRepresentation, error) {
	if v.kcUser == nil {
		var accessToken, err = c.getAccessToken(v)
		if err != nil {
			return nil, err
		}
		if kcUser, err := c.keycloakClient.GetUser(accessToken, v.realmName, v.userID); err == nil {
			v.kcUser = &kcUser
		} else {
			c.logger.Warn(v.ctx, "msg", "Can't get user from Keycloak", "err", err.Error(), "realm", v.realmName, "user", v.userID)
			return nil, err
		}
	}
	return v.kcUser, nil
}

func (c *component) updateKeycloakUser(v *validationContext) error {
	accessToken, err := c.getAccessToken(v)
	if err != nil {
		return err
	}

	err = c.keycloakClient.UpdateUser(accessToken, v.realmName, v.userID, *v.kcUser)
	if err != nil {
		c.logger.Warn(v.ctx, "msg", "updateKeycloakUser: can't update user in KC", "err", err.Error(), "realmName", v.realmName, "userID", v.userID)
		if cde, ok := err.(kc.ClientDetailedError); ok && cde.HTTPStatus == http.StatusBadRequest {
			return err
		}
		return errorhandler.CreateInternalServerError("keycloak")
	}
	return nil
}

func (c *component) archiveUser(v *validationContext) {
	var kcUser, err = c.loadKeycloakUserCtx(v)
	if err != nil {
		return
	}

	var archiveUser = dto.ToArchiveUserRepresentation(*kcUser)
	_ = c.archiveDBModule.StoreUserDetails(v.ctx, v.realmName, archiveUser)
}

func (c *component) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error) {
	var accessToken, err = c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get accessToken for technical user", "err", err.Error())
		return nil, err
	}

	groupsKc, err := c.keycloakClient.GetGroupsOfUser(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	var groupsRep = []api.GroupRepresentation{}
	for _, groupKc := range groupsKc {
		var groupRep api.GroupRepresentation
		groupRep.ID = groupKc.ID
		groupRep.Name = groupKc.Name

		groupsRep = append(groupsRep, groupRep)
	}

	return groupsRep, nil
}
