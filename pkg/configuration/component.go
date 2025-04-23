package configuration

import (
	"context"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

type component struct {
	contextKeyMgr ContextKeyManager
	logger        log.Logger
}

// Component interface
type Component interface {
	GetIdentificationURI(ctx context.Context, realm string, contextKey string) (string, error)
}

// ContextKeyManager interface
type ContextKeyManager interface {
	GetOverride(realm string, contextKey string) (keycloakb.ContextKeyParameters, bool)
}

// NewComponent creates a new Component
func NewComponent(contextKeyManager ContextKeyManager, logger log.Logger) Component {
	return &component{
		contextKeyMgr: contextKeyManager,
		logger:        logger,
	}
}

// GetIdentificationURI returns the identification URI for a given context key and realm
func (c *component) GetIdentificationURI(ctx context.Context, realm string, contextKey string) (string, error) {
	ctxOverride, ok := c.contextKeyMgr.GetOverride(realm, contextKey)
	if !ok {
		c.logger.Info(ctx, "msg", "Invalid (context-key, realm) pair", "context-key", contextKey, "realm", realm)
		return "", errorhandler.CreateBadRequestError(errorhandler.MsgErrInvalidParam + ".realm-and-context-key")
	}

	if ctxOverride.IdentificationURI == nil || *ctxOverride.IdentificationURI == "" {
		c.logger.Info(ctx, "msg", "Empty identification URI", "context-key", contextKey, "realm", realm)
		return "", errorhandler.CreateBadRequestError(errorhandler.MsgErrInvalidParam + ".realm-and-context-key")
	}

	return *ctxOverride.IdentificationURI, nil
}
