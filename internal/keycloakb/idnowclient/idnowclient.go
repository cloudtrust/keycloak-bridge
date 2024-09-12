package idnowclient

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"gopkg.in/h2non/gentleman.v2/plugin"
	"gopkg.in/h2non/gentleman.v2/plugins/headers"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	apiPath              = `/idnow/internal`
	getCheckByNaturePath = apiPath + `/realms/:realm/statistics`

	hdrCorrID    = "X-Correlation-ID"
	prmRealmName = "realm"
)

// IdnowServiceClient interface
type IdnowServiceClient interface {
	GetIdentificationsByType(ctx context.Context, realm string) (IdentificationStatistics, error)
}

// IdentificationStatistics struct
type IdentificationStatistics struct {
	VideoIdentifications int `json:"videoIdentifications"`
	AutoIdentifications  int `json:"autoIdentifications"`
}

// HTTPClient interface
type HTTPClient interface {
	Get(data interface{}, plugins ...plugin.Plugin) error
}

type idnowClient struct {
	httpClient HTTPClient
}

// MakeIdnowServiceClient creates the idnow service client
func MakeIdnowServiceClient(httpClient HTTPClient) IdnowServiceClient {
	return &idnowClient{
		httpClient: httpClient,
	}
}

func (i *idnowClient) GetIdentificationsByType(ctx context.Context, realm string) (IdentificationStatistics, error) {
	var correlationID = ctx.Value(cs.CtContextCorrelationID).(string)
	var stats IdentificationStatistics
	err := i.httpClient.Get(&stats, url.Path(getCheckByNaturePath), url.Param(prmRealmName, realm), headers.Set(hdrCorrID, correlationID))
	return stats, err
}
