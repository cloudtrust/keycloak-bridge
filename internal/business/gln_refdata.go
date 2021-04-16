package business

import (
	"errors"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

const (
	defaultURL  = "https://www.refdata.ch/fr/partenaires/requete/base-de-donnees-des-partenaires-gln"
	regexHeader = `th scope="col".[^>]+>([^<]+)<`
	regexResult = `<td[^>]*>([^<]+)<\/td>`
	resultStart = `<tbody class="dgRow status`
	resultEnd   = `</tbody`
)

type glnRefData struct {
	logger keycloakb.Logger
}

func NewRefDataLookup(logger keycloakb.Logger) GlnLookupProvider {
	return &glnRefData{
		logger: logger,
	}
}

func (l *glnRefData) Lookup(gln string) GlnDetails {
	return GlnDetails{Error: errors.New("not yet implemented")}
}
