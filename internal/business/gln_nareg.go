package business

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/cloudtrust/httpclient"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
	"gopkg.in/h2non/gentleman.v2/plugin"
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/headers"
	"gopkg.in/h2non/gentleman.v2/plugins/query"
	gurl "gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	naRegReqParams = `sort=PersonLastName-asc~PersonFirstName-asc&page=1&pageSize=10&group=&filter=`
)

type naRegResult struct {
	Data             []naRegData `json:"Data"`
	Total            *int        `json:"Total"`
	AggregateResults interface{} `json:"AggregateResults"`
	Errors           interface{} `json:"Errors"`
}

type naRegData struct {
	Addresses                             []naRegAddress `json:"Addresses"`
	PersonLastName                        *string        `json:"PersonLastName"`
	PersonIsAnonymized                    *bool          `json:"PersonIsAnonymized"`
	PersonID                              *int           `json:"PersonId"`
	DuplicatePersonID                     interface{}    `json:"DuplicatePersonId"`
	DuplicateMode                         *bool          `json:"DuplicateMode"`
	PersonGlnNumber                       *string        `json:"PersonGlnNumber"`
	PersonFirstName                       *string        `json:"PersonFirstName"`
	LicenceID                             *int           `json:"LicenceId"`
	CodeTranslationLicenceCantonLabel     *string        `json:"CodeTranslationLicenceCantonLabel"`
	CodeTranslationDiplomaProfessionLabel *string        `json:"CodeTranslationDiplomaProfessionLabel"`
	CodePersonSexID                       *int           `json:"CodePersonSexId"`
	CodeLicenceStatusID                   interface{}    `json:"CodeLicenceStatusId"`
	CodeLicenceProfessionID               interface{}    `json:"CodeLicenceProfessionId"`
	CodeLicenceLicenceTypeID              interface{}    `json:"CodeLicenceLicenceTypeId"`
	CodeLicenceCantonID                   *int           `json:"CodeLicenceCantonId"`
	CodeDiplomaProfessionID               *int           `json:"CodeDiplomaProfessionId"`
	AddressZip                            interface{}    `json:"AddressZip"`
	AddressStreet                         interface{}    `json:"AddressStreet"`
	AddressPlace                          interface{}    `json:"AddressPlace"`
	AddressID                             interface{}    `json:"AddressId"`
}

type naRegAddress struct {
	ID     *int    `json:"Id"`
	Street *string `json:"Street"`
	Zip    *string `json:"Zip"`
	Place  *string `json:"Place"`
}

type naReg struct {
	client   *httpclient.Client
	origin   string
	formPath string
	referer  string
	logger   keycloakb.Logger
}

// NewNaRegLookup creates a GLN lookup provider using nareg website
func NewNaRegLookup(baseURL string, httpTimeout time.Duration, logger keycloakb.Logger) (GlnLookupProvider, error) {
	var client, err = httpclient.New(baseURL, httpTimeout)
	if err != nil {
		return nil, err
	}
	return &naReg{
		client:   client,
		formPath: "/Search/Read",
		origin:   baseURL,
		referer:  baseURL + "/",
		logger:   logger,
	}, nil
}

func (l *naReg) Lookup(gln string) GlnSearchResult {
	var result, err = l.request(gln)
	if err != nil {
		return GlnSearchResult{Error: err}
	}
	return l.jsonToDetails(gln, result)
}

func (l *naReg) request(gln string) (naRegResult, error) {
	var plugins []plugin.Plugin
	plugins = append(plugins,
		gurl.Path(l.formPath),
		query.Add("PersonGlnNumber", gln),
		headers.Set("Accept", "*/*"),
		headers.Set("Content-Length", fmt.Sprintf("%d", utf8.RuneCountInString(naRegReqParams))),
		headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),
		headers.Set("Origin", l.origin),
		headers.Set("Referer", l.referer),
		body.String(naRegReqParams))
	var response naRegResult
	var _, err = l.client.Post(&response, plugins...)
	if err != nil {
		l.logger.Warn(context.Background(), "msg", "Can't get response from naReg", "err", err.Error(), "gln", gln)
		return naRegResult{}, errors.Wrap(err, keycloak.MsgErrCannotObtain+"."+keycloak.Response)
	}
	return response, nil
}

func (l *naReg) jsonToDetails(gln string, response naRegResult) GlnSearchResult {
	if len(response.Data) == 0 {
		return GlnSearchResult{Error: ErrGLNNotFound}
	}
	var result []GlnPerson
	for _, person := range response.Data {
		var (
			active  = true
			zipCode *string
			city    *string
			canton  *string
		)
		if len(person.Addresses) > 0 {
			zipCode = person.Addresses[0].Zip
			city = person.Addresses[0].Place
		}
		result = append(result, GlnPerson{
			Active:     &active,
			Number:     &gln,
			FirstName:  person.PersonFirstName,
			LastName:   person.PersonLastName,
			Canton:     canton,
			ZipCode:    zipCode,
			City:       city,
			Country:    nil,
			Profession: person.CodeTranslationDiplomaProfessionLabel,
		})
	}
	return GlnSearchResult{Persons: result, Error: nil}
}
