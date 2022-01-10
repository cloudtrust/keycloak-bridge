package keycloakb

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"gopkg.in/h2non/gentleman.v2/plugin"
	"gopkg.in/h2non/gentleman.v2/plugins/headers"
	"gopkg.in/h2non/gentleman.v2/plugins/query"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	getBalancePath = "/internal/realms/:realm/users/:userID/balance"

	prmUserID    = "userID"
	prmRealmName = "realm"
	prmService   = "service"
	hdrCorrID    = "X-Correlation-ID"
)

type AccountingClient struct {
	httpClient HttpClient
}

type HttpClient interface {
	Get(data interface{}, plugins ...plugin.Plugin) error
}

type AccountingBalance struct {
	Balance *float64 `json:"balance"`
}

func MakeAccountingClient(httpClient HttpClient) *AccountingClient {
	return &AccountingClient{
		httpClient: httpClient,
	}
}

func (c *AccountingClient) GetBalance(ctx context.Context, realmName string, userID string, service string) (float64, error) {
	var correlationID = ctx.Value(cs.CtContextCorrelationID).(string)
	var res AccountingBalance
	err := c.httpClient.Get(&res, url.Path(getBalancePath), url.Param(prmRealmName, realmName), url.Param(prmUserID, userID), query.Add(prmService, service), headers.Set(hdrCorrID, correlationID))
	if err != nil {
		return 0, err
	}
	return *res.Balance, nil
}
