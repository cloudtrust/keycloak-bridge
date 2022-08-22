package accreditationsclient

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service/v2"
	"gopkg.in/h2non/gentleman.v2/plugin"
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/headers"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

// AccreditationsServiceClient interface
type AccreditationsServiceClient interface {
	NotifyCheck(ctx context.Context, check CheckRepresentation) error
	NotifyUpdate(ctx context.Context, updateNotifyRequest UpdateNotificationRepresentation) ([]string, error)
}

// UpdateNotificationRepresentation struct
type UpdateNotificationRepresentation struct {
	UserID        *string  `json:"userId"`
	RealmName     *string  `json:"realmName"`
	UpdatedFields []string `json:"updatedFields,omitempty"`
}

// CheckRepresentation struct
type CheckRepresentation struct {
	UserID    *string    `json:"userId,omitempty"`
	RealmName *string    `json:"realmName,omitempty"`
	Operator  *string    `json:"operator,omitempty"`
	DateTime  *time.Time `json:"datetime,omitempty"`
	Status    *string    `json:"status,omitempty"`
	Type      *string    `json:"type,omitempty"`
	Nature    *string    `json:"nature,omitempty"`
	ProofData *[]byte    `json:"proofData,omitempty"`
	ProofType *string    `json:"proofType,omitempty"`
	Comment   *string    `json:"comment,omitempty"`
	TxnID     *string    `json:"txnId,omitempty"`
}

// HTTPClient interface
type HTTPClient interface {
	Post(data interface{}, plugins ...plugin.Plugin) (string, error)
	Put(plugins ...plugin.Plugin) error
}

type accreditationsClient struct {
	httpClient HTTPClient
}

const (
	apiPath          = `/internal/backend`
	updateCheckPath  = apiPath + `/notify-check`
	updateNotifyPath = apiPath + `/notify-update`

	hdrCorrID = "X-Correlation-ID"
)

// MakeAccreditationsServiceClient creates the accreditations service client
func MakeAccreditationsServiceClient(httpClient HTTPClient) *accreditationsClient {
	return &accreditationsClient{
		httpClient: httpClient,
	}
}

// UpdateCheck informs the accreditations service that a new check should be registered
func (ac *accreditationsClient) NotifyCheck(ctx context.Context, check CheckRepresentation) error {
	var correlationID = ctx.Value(cs.CtContextCorrelationID).(string)
	return ac.httpClient.Put(url.Path(updateCheckPath), headers.Set(hdrCorrID, correlationID), body.JSON(check))
}

// UpdateNotify informs the accreditations service that we are updating some user fields. In response, we will be told which accreditations should be revoked
func (ac *accreditationsClient) NotifyUpdate(ctx context.Context, updateNotifyRequest UpdateNotificationRepresentation) ([]string, error) {
	var correlationID = ctx.Value(cs.CtContextCorrelationID).(string)
	var res []string
	var _, err = ac.httpClient.Post(&res, url.Path(updateNotifyPath), headers.Set(hdrCorrID, correlationID), body.JSON(updateNotifyRequest))
	return res, err
}
