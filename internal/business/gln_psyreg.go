package business

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloudtrust/httpclient"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
	"gopkg.in/h2non/gentleman.v2/plugin"
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/headers"
	gurl "gopkg.in/h2non/gentleman.v2/plugins/url"
)

type PsyRegResponse struct {
	Count             *int           `json:"personenCount"`
	MaxResultExceeded *bool          `json:"maxResultExceeded"`
	Persons           []PsyRegPerson `json:"personen"`
}

type PsyRegPerson struct {
	ID               *int             `json:"personId"`
	FirstName        *string          `json:"vorname"`
	LastName         *string          `json:"name"`
	ProfessionID     *int             `json:"berufsbezeichnungId"`
	Languages        []int            `json:"sprachIds"`
	Locations        []PsyRegLocation `json:"plzOrtCollection"`
	CantonID         *int             `json:"kantonId"`
	ApprovalStatusID *int             `json:"bewilligungsstatusId"`
	TooLongName      interface{}      `json:"isMeldungNeunzigTageDienstleisterCurrentYear"`
}

type PsyRegLocation struct {
	ZipCode *string `json:"plz"`
	City    *string `json:"ort"`
}

const (
	psyRegReqParams = `{"advancedSearchActive":false,"kantonId":null,"gln":"##GLN##","currentPage":0,"ort":"Lausanne","name":"","vorname":"","plz":""}`
)

type psyReg struct {
	client   *httpclient.Client
	origin   string
	formPath string
	referer  string
	logger   keycloakb.Logger
}

// NewPsyRegLookup creates a GLN lookup tool using psyreg.admin.ch
func NewPsyRegLookup(baseURL string, httpTimeout time.Duration, logger keycloakb.Logger) (GlnLookupProvider, error) {
	var client, err = httpclient.New(baseURL, httpTimeout)
	if err != nil {
		return nil, err
	}

	var origin = strings.ReplaceAll(baseURL, "ws.", "www.")
	origin = strings.ReplaceAll(origin, ".bag.", ".")

	return &psyReg{
		client:   client,
		formPath: "/api/personen/search",
		origin:   origin,
		referer:  origin + "/",
		logger:   logger,
	}, nil
}

func (l *psyReg) Lookup(gln string) GlnSearchResult {
	if details, err := l.request(gln); err != nil {
		return GlnSearchResult{Error: err}
	} else {
		return l.jsonToDetails(gln, details)
	}
}

func (l *psyReg) request(gln string) (PsyRegResponse, error) {
	var bodyValue = strings.ReplaceAll(psyRegReqParams, "##GLN##", gln)
	var plugins []plugin.Plugin
	plugins = append(plugins,
		gurl.Path(l.formPath),
		headers.Set("Accept", "application/json, text/plain, */*"),
		headers.Set("Content-Length", fmt.Sprintf("%d", utf8.RuneCountInString(bodyValue))),
		headers.Set("Content-Type", "application/json;charset=UTF-8"),
		headers.Set("Origin", l.origin),
		headers.Set("Referer", l.referer),
		body.String(bodyValue),
	)
	var response PsyRegResponse
	if _, err := l.client.Post(&response, plugins...); err != nil {
		l.logger.Warn(context.Background(), "msg", "Can't get response from psyReg", "err", err.Error(), "gln", gln)
		return PsyRegResponse{}, errors.Wrap(err, keycloak.MsgErrCannotObtain+"."+keycloak.Response)
	} else {
		return response, nil
	}
}

func (l *psyReg) jsonToDetails(gln string, response PsyRegResponse) GlnSearchResult {
	if *response.Count == 0 {
		return GlnSearchResult{Error: ErrGLNNotFound}
	}
	var result []GlnPerson
	for _, person := range response.Persons {
		var (
			active     = true
			zipCode    *string
			city       *string
			canton     *string
			profession *string
		)
		if person.CantonID != nil {
			var value = fmt.Sprintf("%d", *person.CantonID)
			canton = &value
		}
		if person.ProfessionID != nil {
			var value = fmt.Sprintf("%d", *person.ProfessionID)
			profession = &value
		}
		if len(person.Locations) > 0 {
			zipCode = person.Locations[0].ZipCode
			city = person.Locations[0].City
		}
		result = append(result, GlnPerson{
			Active:     &active,
			Number:     &gln,
			FirstName:  person.FirstName,
			LastName:   person.LastName,
			Canton:     canton,
			ZipCode:    zipCode,
			City:       city,
			Country:    nil,
			Profession: profession,
		})
	}
	return GlnSearchResult{Persons: result, Error: nil}
}
