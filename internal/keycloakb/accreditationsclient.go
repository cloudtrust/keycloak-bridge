package keycloakb

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/headers"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

// AccreditationsServiceClient interface
type AccreditationsServiceClient interface {
	UpdateCheck(ctx context.Context, realmName string, userID string, check interface{}) error
	UpdateNotify(ctx context.Context, realmName string, userID string, accredsRequest AccredsNotifyRepresentation) ([]string, error)
}

// AccredsNotifyRepresentation struct
type AccredsNotifyRepresentation struct {
	UpdatedFields []string `json:"updatedFields,omitempty"`
}

type accreditationsClient struct {
	httpClient HTTPClient
}

const (
	userPath         = `/internal/realms/:realm/users/:userId`
	updateCheckPath  = userPath + `/notify-check`
	updateNotifyPath = userPath + `/notify-update`
)

// MakeAccreditationsServiceClient creates the accreditations service client
func MakeAccreditationsServiceClient(httpClient HTTPClient) *accreditationsClient {
	return &accreditationsClient{
		httpClient: httpClient,
	}
}

// UpdateCheck informs the accreditations service that a new check should be registered
func (ac *accreditationsClient) UpdateCheck(ctx context.Context, realmName string, userID string, check interface{}) error {
	var correlationID = ctx.Value(cs.CtContextCorrelationID).(string)
	var _, err = ac.httpClient.Post(url.Path(updateCheckPath), url.Param(prmRealmName, realmName), url.Param(prmUserID, userID),
		headers.Set(hdrCorrID, correlationID), body.JSON(check))
	return err
}

// UpdateNotify informs the accreditations service that we are updating some user fields. In response, we will be told which accreditations should be revoked
func (ac *accreditationsClient) UpdateNotify(ctx context.Context, realmName string, userID string, accredsRequest AccredsNotifyRepresentation) ([]string, error) {
	var correlationID = ctx.Value(cs.CtContextCorrelationID).(string)
	var res []string
	var err = ac.httpClient.Get(&res, url.Path(updateNotifyPath), url.Param(prmRealmName, realmName), url.Param(prmUserID, userID),
		headers.Set(hdrCorrID, correlationID), body.JSON(accredsRequest))
	return res, err
}
