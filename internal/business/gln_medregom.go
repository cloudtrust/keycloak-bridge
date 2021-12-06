package business

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloudtrust/httpclient"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-client/v2"
	"github.com/pkg/errors"
	"gopkg.in/h2non/gentleman.v2/plugin"
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/headers"
	gurl "gopkg.in/h2non/gentleman.v2/plugins/url"
)

// MedRegResponse struct
type MedRegResponse struct {
	EmptyRowData   interface{}    `json:"emptyrowdata"`
	Rows           []MedRegPerson `json:"rows"`
	Settings       interface{}    `json:"settings"`
	AdditionalInfo interface{}    `json:"additionalInfo"`
}

// MedRegPerson struct
type MedRegPerson struct {
	ID         *int     `json:"Id"`
	FirstName  *string  `json:"FirstName"`
	LastName   *string  `json:"LastName"`
	Profession *string  `json:"Beruf"`
	Street     []string `json:"Strasse"`
	ZipCode    []string `json:"Plz"`
	Location   []string `json:"Ort"`
	Score      *int     `json:"Score"`
	Education  *string  `json:"Weiterbildungen"`
}

const (
	medRegReqParams = `currentpage=1&pagesize=10&sortfield=&sortorder=Ascending&pageraction=&filter=&Diplome.1=false&Diplome.999999=false&Diplome.3=false&Diplome.5=false&Diplome.2=false&Diplome.4=false&Name=&Vorname=&Strasse=&Plz=&Ort=&Kanton=-&Gln=##GLN##&Bewilligungen.5002=false&Geschlecht=999998&Spezialisierungen.1019=false&Spezialisierungen.1012=false&Spezialisierungen.1041=false&Spezialisierungen.1025=false&Spezialisierungen.1002=false&Spezialisierungen.1004=false&Spezialisierungen.1059=false&Spezialisierungen.1026=false&Spezialisierungen.1015=false&Spezialisierungen.1028=false&Spezialisierungen.1035=false&Spezialisierungen.1061=false&Spezialisierungen.1060=false&Spezialisierungen.1021=false&Spezialisierungen.1022=false&Spezialisierungen.1023=false&Spezialisierungen.1043=false&Spezialisierungen.1003=false&Spezialisierungen.1024=false&Spezialisierungen.1033=false&Spezialisierungen.1039=false&Spezialisierungen.1040=false&Spezialisierungen.1020=false&Spezialisierungen.1042=false&Spezialisierungen.1051=false&Spezialisierungen.1046=false&Spezialisierungen.1031=false&Spezialisierungen.1045=false&Spezialisierungen.1034=false&Spezialisierungen.1038=false&Spezialisierungen.1013=false&Spezialisierungen.1014=false&Spezialisierungen.1044=false&Spezialisierungen.1007=false&Spezialisierungen.1008=false&Spezialisierungen.1009=false&Spezialisierungen.1006=false&Spezialisierungen.1029=false&Spezialisierungen.1016=false&Spezialisierungen.1036=false&Spezialisierungen.1017=false&Spezialisierungen.1027=false&Spezialisierungen.1030=false&Spezialisierungen.1032=false&Spezialisierungen.1037=false&Spezialisierungen.1018=false&Spezialisierungen.1011=false&Spezialisierungen.1047=false&Spezialisierungen.1049=false&Spezialisierungen.1010=false&Spezialisierungen.1048=false&Spezialisierungen.1062=false&Spezialisierungen.1052=false&Spezialisierungen.1053=false&Weiterbildungen.2176=false&Weiterbildungen.2030=false&Weiterbildungen.2014=false&Weiterbildungen.2021=false&Weiterbildungen.2195=false&Weiterbildungen.2002=false&Weiterbildungen.2005=false&Weiterbildungen.2034=false&Weiterbildungen.2023=false&Weiterbildungen.2098=false&Weiterbildungen.2032=false&Weiterbildungen.2033=false&Weiterbildungen.2012=false&Weiterbildungen.2046=false&Weiterbildungen.2013=false&Weiterbildungen.2035=false&Weiterbildungen.2001=false&Weiterbildungen.2095=false&Weiterbildungen.2162=false&Weiterbildungen.2054=false&Weiterbildungen.2039=false&Weiterbildungen.2037=false&Weiterbildungen.2051=false&Weiterbildungen.2096=false&Weiterbildungen.2040=false&Weiterbildungen.2184=false&Weiterbildungen.2008=false&Weiterbildungen.2050=false&Weiterbildungen.2090=false&Weiterbildungen.2188=false&Weiterbildungen.2049=false&Weiterbildungen.2170=false&Weiterbildungen.2007=false&Weiterbildungen.2038=false&Weiterbildungen.2177=false&Weiterbildungen.2043=false&Weiterbildungen.2015=false&Weiterbildungen.2016=false&Weiterbildungen.2089=false&Weiterbildungen.2017=false&Weiterbildungen.2027=false&Weiterbildungen.2028=false&Weiterbildungen.2171=false&Weiterbildungen.2006=false&Weiterbildungen.2018=false&Weiterbildungen.2020=false&Weiterbildungen.2024=false&Weiterbildungen.2103=false&Weiterbildungen.2041=false&Weiterbildungen.2022=false&Weiterbildungen.2163=false&Weiterbildungen.2019=false&Weiterbildungen.2042=false&Weiterbildungen.2102=false&Weiterbildungen.2025=false&Weiterbildungen.2179=false&Weiterbildungen.2169=false&Weiterbildungen.2168=false&Weiterbildungen.2187=false&Weiterbildungen.2031=false&Weiterbildungen.2045=false&Weiterbildungen.2026=false&Weiterbildungen.2044=false&Weiterbildungen.2161=false&Weiterbildungen.2193=false&Weiterbildungen.2164=false&Weiterbildungen.2192=false&Weiterbildungen.2101=false&Weiterbildungen.2052=false&Weiterbildungen.2036=false&Weiterbildungen.2055=false&Weiterbildungen.2194=false&Weiterbildungen.2091=false&Weiterbildungen.2048=false&Weiterbildungen.2185=false&Weiterbildungen.2047=false&Weiterbildungen.2174=false&Weiterbildungen.2175=false&Weiterbildungen.2029=false&Weiterbildungen.2190=false&Weiterbildungen.2191=false&Weiterbildungen.2057=false&Weiterbildungen.2160=false&Weiterbildungen.2059=false&Weiterbildungen.2058=false&Weiterbildungen.2056=false&Weiterbildungen.2180=false&Weiterbildungen.2066=false&Weiterbildungen.2186=false&Weiterbildungen.2093=false&Weiterbildungen.2065=false&Weiterbildungen.2067=false&Weiterbildungen.2172=false&Weiterbildungen.2166=false&Weiterbildungen.2064=false&Weiterbildungen.2062=false&Weiterbildungen.2063=false&Weiterbildungen.2061=false&Weiterbildungen.2082=false&Weiterbildungen.2081=false&Weiterbildungen.2182=false&Weiterbildungen.2183=false&Weiterbildungen.2085=false&Weiterbildungen.2167=false&Weiterbildungen.2077=false&Weiterbildungen.2178=false&Weiterbildungen.2104=false&Weiterbildungen.2078=false&Weiterbildungen.2107=false&Weiterbildungen.2165=false&Weiterbildungen.2106=false&Weiterbildungen.2189=false&Weiterbildungen.2076=false&Weiterbildungen.2181=false&Weiterbildungen.2148=false&Weiterbildungen.2119=false&Weiterbildungen.2127=false&Weiterbildungen.2124=false&Weiterbildungen.2122=false&Weiterbildungen.2129=false&Weiterbildungen.2159=false&Weiterbildungen.2126=false&Weiterbildungen.2121=false&Weiterbildungen.2125=false&Weiterbildungen.2110=false&Weiterbildungen.2115=false&Weiterbildungen.2157=false&Weiterbildungen.2112=false&Weiterbildungen.2154=false&Weiterbildungen.2117=false&Weiterbildungen.2123=false&Weiterbildungen.2118=false&Weiterbildungen.2152=false&Weiterbildungen.2113=false&Weiterbildungen.2120=false&Weiterbildungen.2128=false&Weiterbildungen.2097=false&Weiterbildungen.2173=false&Weiterbildungen.2105=false&Weiterbildungen.2070=false&Weiterbildungen.2069=false&Weiterbildungen.2068=false&Weiterbildungen.2072=false&Weiterbildungen.2071=false&Weiterbildungen.2073=false&AutomatischeSuche=False`
)

type medRegOm struct {
	client   *httpclient.Client
	origin   string
	formPath string
	referer  string
	logger   keycloakb.Logger
}

// NewMedRegOmLookup creates a GLN lookup tool using medregom.admin.ch
func NewMedRegOmLookup(baseURL string, httpTimeout time.Duration, logger keycloakb.Logger) (GlnLookupProvider, error) {
	var client, err = httpclient.New(baseURL, httpTimeout)
	if err != nil {
		return nil, err
	}

	return &medRegOm{
		client:   client,
		formPath: baseURL + "/FR/Suche/GetSearchData",
		origin:   baseURL,
		referer:  baseURL + "/",
		logger:   logger,
	}, nil
}

func (l *medRegOm) Lookup(gln string) GlnSearchResult {
	var resp, err = l.request(gln)
	if err != nil {
		return GlnSearchResult{Error: err}
	}
	return l.responseToDetails(gln, resp)
}

func (l *medRegOm) request(gln string) (MedRegResponse, error) {
	var bodyValue = strings.ReplaceAll(medRegReqParams, "##GLN##", gln)
	var plugins []plugin.Plugin
	plugins = append(plugins,
		gurl.Path(l.formPath),
		headers.Set("Content-Length", fmt.Sprintf("%d", utf8.RuneCountInString(bodyValue))),
		headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),
		headers.Set("Origin", l.origin),
		headers.Set("Referer", l.referer),
		body.String(bodyValue))
	var response MedRegResponse
	var _, err = l.client.Post(&response, plugins...)
	if err != nil {
		l.logger.Warn(context.Background(), "msg", "Can't get response from medReg", "err", err.Error(), "gln", gln)
		return MedRegResponse{}, errors.Wrap(err, keycloak.MsgErrCannotObtain+"."+keycloak.Response)
	}
	return response, nil
}

func (l *medRegOm) responseToDetails(gln string, response MedRegResponse) GlnSearchResult {
	if len(response.Rows) == 0 {
		return GlnSearchResult{Error: ErrGLNNotFound}
	}
	var result []GlnPerson
	for _, person := range response.Rows {
		var (
			active  = true
			zipCode *string
			city    *string
		)
		if len(person.ZipCode) > 0 {
			zipCode = &person.ZipCode[0]
		}
		if len(person.Location) > 0 {
			city = &person.Location[0]
		}
		result = append(result, GlnPerson{
			Active:     &active,
			Number:     &gln,
			FirstName:  person.FirstName,
			LastName:   person.LastName,
			Canton:     nil,
			ZipCode:    zipCode,
			City:       city,
			Country:    nil,
			Profession: person.Profession,
		})
	}
	return GlnSearchResult{Persons: result, Error: nil}
}
