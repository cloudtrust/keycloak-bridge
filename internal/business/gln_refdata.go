package business

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	errorhandler "github.com/cloudtrust/common-service/errors"
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

var (
	headerParser = regexp.MustCompile(`th scope="col".[^>]+>([^<]+)<`)
	resultParser = regexp.MustCompile(`<td[^>]*>([^<]+)`)
	npaParser    = regexp.MustCompile(`^(\d+)\s+(.+)$`)
)

const (
	resultStart       = `<tbody class="dgRow status`
	resultEnd         = `</tbody`
	allResultsEnd     = `</tabl`
	MsgErrCannotParse = "cannotParse"
)

type glnRefData struct {
	client         *httpclient.Client
	origin         string
	searchPagePath string
	formPath       string
	referer        string
	logger         keycloakb.Logger
}

// NewRefDataLookup creates a GLN lookup tool using refdata.ch
func NewRefDataLookup(baseURL string, httpTimeout time.Duration, logger keycloakb.Logger) (GlnLookupProvider, error) {
	// Search page: https://www.refdata.ch/fr/partenaires/requete/base-de-donnees-des-partenaires-gln
	// Form: https://refdatabase.refdata.ch/Viewer/SearchPartnerByGln?Lang=fr
	// Origin: https://refdatabase.refdata.ch
	// Referer: https://refdatabase.refdata.ch/Viewer/Partner/?Lang=FR
	var client, err = httpclient.New(baseURL, httpTimeout)
	if err != nil {
		return nil, err
	}

	return &glnRefData{
		client:         client,
		origin:         baseURL,
		searchPagePath: "/fr/partenaires/requete/base-de-donnees-des-partenaires-gln",
		formPath:       "/Viewer/SearchPartnerByGln",
		referer:        baseURL + "/Viewer/Partner/?Lang=FR",
		logger:         logger,
	}, nil
}

func (l *glnRefData) Lookup(gln string) GlnSearchResult {
	if html, err := l.request(gln); err != nil {
		return GlnSearchResult{Error: err}
	} else {
		return l.htmlToDetails(gln, html)
	}
}

func (l *glnRefData) request(gln string) (string, error) {
	var bodyValue = fmt.Sprintf("SearchGln=%s&Sort=&NewSort=&IsAscending=False&Reset=False", gln)
	var plugins []plugin.Plugin
	plugins = append(plugins,
		gurl.Path(l.formPath),
		query.Add("Lang", "fr"),
		headers.Set("Content-Length", fmt.Sprintf("%d", utf8.RuneCountInString(bodyValue))),
		headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),
		headers.Set("Origin", l.origin),
		headers.Set("Referer", l.referer),
		body.String(bodyValue),
	)

	var response string
	if _, err := l.client.Post(&response, plugins...); err != nil {
		l.logger.Warn(context.Background(), "msg", "Can't get response from psyReg", "err", err.Error(), "gln", gln)
		return "", errors.Wrap(err, keycloak.MsgErrCannotObtain+"."+keycloak.Response)
	} else {
		return response, nil
	}
}

func (l *glnRefData) htmlToDetails(gln string, html string) GlnSearchResult {
	// Get headers
	var matchedHeaders = headerParser.FindAllStringSubmatch(html, -1)
	var resHeaders []string
	for _, m := range matchedHeaders {
		resHeaders = append(resHeaders, m[1])
	}

	if len(resHeaders) == 0 {
		return GlnSearchResult{Error: ErrGLNNotFound}
	}

	var start = strings.Index(html, resultStart)
	var end = strings.LastIndex(html, allResultsEnd)
	if start < 0 || end < start {
		return GlnSearchResult{Error: errorhandler.CreateInternalServerError("gln.refData.invalidResponse")}
	}

	var result []GlnPerson
	for _, personHtml := range strings.Split(html[start+1:end], resultStart) {
		var matchedDetails = resultParser.FindAllStringSubmatch(personHtml, -1)
		var maxIndex = len(matchedDetails)
		if maxIndex > len(resHeaders) {
			maxIndex = len(resHeaders)
		}
		var details = make(map[string]string)
		for i := 0; i < maxIndex; i++ {
			details[resHeaders[i]] = matchedDetails[i][1]
		}

		var strActive = l.getValue(details, "Statut")
		var active = strActive != nil && *strActive == "A"
		var person = GlnPerson{
			Active:     &active,
			Number:     l.getValue(details, "GLN"),
			FirstName:  l.getValue(details, "Pr&#233;nom"),
			LastName:   l.getValue(details, "Nom"),
			Canton:     l.getValue(details, "Ctn"),
			ZipCode:    nil,
			City:       nil,
			Country:    l.getValue(details, "Pays"),
			Profession: l.getValue(details, "Profession"),
		}
		var npa = l.getValue(details, "NPA")
		if npa != nil {
			var matched = npaParser.FindAllStringSubmatch(*npa, -1)
			if len(matched) == 1 && len(matched[0]) == 3 {
				person.ZipCode = &matched[0][1]
				person.City = &matched[0][2]
			}
		}
		result = append(result, person)
	}

	return GlnSearchResult{Persons: result, Error: nil}
}

func (l *glnRefData) getValue(details map[string]string, field string) *string {
	if value, ok := details[field]; ok {
		return &value
	}
	return nil
}
