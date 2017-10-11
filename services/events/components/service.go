package components

import (
	"context"
	"github.com/cloudtrust/keycloak-bridge/services/events/modules/console"
)

/*
This is the interface that user services implement.
 */
type Service interface {
	ConsumeEvents(ctx context.Context, realm string)
}

/*
 */
func NewBasicService(consoleModule console.Service) Service {
	return &basicService{
		module:consoleModule,
	}
}

type basicService struct {
	module console.Service
}

func (u *basicService)ConsumeEvents(ctx context.Context, realm string) {
	u.module.PrintEvent(ctx, realm)
}

