package business

import (
	"context"
	"encoding/xml"
	"fmt"
	"regexp"
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
)

var (
	soapRequest = strings.Trim(`
	<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	  <soap:Body>
		<DownloadPartnerInput xmlns="http://refdatabase.refdata.ch/">
		  <TYPE xmlns="http://refdatabase.refdata.ch/Partner_in">GLN</TYPE>
		  <PTYPE xmlns="http://refdatabase.refdata.ch/Partner_in">ALL</PTYPE>
		  <TERM xmlns="http://refdatabase.refdata.ch/Partner_in">##GLN##</TERM>
		</DownloadPartnerInput>
	  </soap:Body>
	</soap:Envelope>
	`, " \r\n\t")
)

type soapPartnerResponse struct {
	XMLName xml.Name    `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	XSI     *string     `xml:"xmlns:xsi,attr"`
	XSD     *string     `xml:"xmlns:xsd,attr"`
	Header  interface{} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`
	Body    struct {
		Partner struct {
			Creation  *string `xml:"CREATION_DATETIME,attr"`
			Namespace *string `xml:"xmlns,attr"`
			Result    struct {
				Namespace *string `xml:"xmlns,attr"`
				OkError   *string `xml:"OK_ERROR"`
				NbrRecord *int    `xml:"NBR_RECORD"`
			} `xml:"RESULT"`
			Items []soapItem `xml:"ITEM"`
		} `xml:"PARTNER"`
	} `xml:"Body"`
}

type soapItem struct {
	Date        *string `xml:"DT,attr"`
	Namespace   *string `xml:"xmlns,attr"`
	PartnerType *string `xml:"PTYPE,omitempty"`
	GLN         *string `xml:"GLN,omitempty"`
	Status      *string `xml:"STATUS,omitempty"`
	StartDate   *string `xml:"STDATE,omitempty"`
	Language    *string `xml:"LANG,omitempty"`
	LastName    *string `xml:"DESCR1,omitempty"`
	FirstName   *string `xml:"DESCR2,omitempty"`
	Role        struct {
		Type    *string `xml:"TYPE,omitempty"`
		ZipCode *string `xml:"ZIP,omitempty"`
		City    *string `xml:"CITY,omitempty"`
		Canton  *string `xml:"CTN,omitempty"`
		Country *string `xml:"CNTRY,omitempty"`
	} `xml:"ROLE,omitempty"`
}

type glnRefData struct {
	client     *httpclient.Client
	soapAction string
	logger     keycloakb.Logger
}

// NewRefDataLookup creates a GLN lookup tool using refdata.ch
func NewRefDataLookup(baseURL string, httpTimeout time.Duration, logger keycloakb.Logger) (GlnLookupProvider, error) {
	var client, err = httpclient.New(baseURL, httpTimeout)
	if err != nil {
		return nil, err
	}

	var soapAction = "http://refdatabase.refdata.ch/Download"
	re := regexp.MustCompile(`/`)
	idx := re.FindAllIndex([]byte(baseURL), 3)
	if len(idx) > 2 {
		// First 2 slashes are the ones between the protocol and the server name. We split starting of the third one
		soapAction = strings.ReplaceAll(baseURL[0:idx[2][0]], "https", "http") + "/Download"
	}

	return &glnRefData{
		client:     client,
		soapAction: soapAction,
		logger:     logger,
	}, nil
}

func (l *glnRefData) Lookup(gln string) GlnSearchResult {
	var bytes, err = l.request(gln)
	if err != nil {
		return GlnSearchResult{Error: err}
	}
	return l.xmlToDetails(gln, bytes)
}

func (l *glnRefData) request(gln string) ([]byte, error) {
	var bodyValue = strings.ReplaceAll(soapRequest, "##GLN##", gln)
	var plugins []plugin.Plugin
	plugins = append(plugins,
		headers.Set("Content-Type", "text/xml; charset=utf-8"),
		headers.Set("Content-Length", fmt.Sprintf("%d", utf8.RuneCountInString(bodyValue))),
		headers.Set("SOAPAction", l.soapAction),
		body.String(bodyValue),
	)

	var response []byte
	var _, err = l.client.Post(&response, plugins...)
	if err != nil {
		l.logger.Warn(context.Background(), "msg", "Can't get response from refData", "err", err.Error(), "gln", gln)
		return nil, errors.Wrap(err, keycloak.MsgErrCannotObtain+"."+keycloak.Response)
	}
	return response, nil
}

func (l *glnRefData) xmlToDetails(gln string, xmlContent []byte) GlnSearchResult {
	var response soapPartnerResponse
	if err := xml.Unmarshal(xmlContent, &response); err != nil {
		return GlnSearchResult{Error: ErrGLNCantParse}
	}
	if response.Body.Partner.Result.OkError == nil || *response.Body.Partner.Result.OkError != "OK" {
		l.logger.Info(context.Background(), "msg", "Failed to request GLN through refdata", "gln", gln)
		return GlnSearchResult{Error: ErrGLNNotFound}
	}
	if response.Body.Partner.Result.NbrRecord == nil || *response.Body.Partner.Result.NbrRecord == 0 {
		return GlnSearchResult{Error: ErrGLNNotFound}
	}
	var result []GlnPerson
	for _, item := range response.Body.Partner.Items {
		var active = item.Status != nil && *item.Status == "A"
		result = append(result, GlnPerson{
			Active:     &active,
			Number:     item.GLN,
			FirstName:  item.FirstName,
			LastName:   item.LastName,
			ZipCode:    item.Role.ZipCode,
			City:       item.Role.City,
			Canton:     item.Role.Canton,
			Country:    item.Role.Country,
			Profession: item.Role.Type,
		})
	}
	return GlnSearchResult{
		Persons: result,
		Error:   nil,
	}
}
