package keycloakb

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/stretchr/testify/assert"
)

func makeDummyEndpoint() cs.Endpoint {
	return func(_ context.Context, _ interface{}) (response interface{}, err error) {
		return "dummy", nil
	}
}

func TestLimitRate(t *testing.T) {
	res, err := LimitRate(makeDummyEndpoint(), 1000)(context.TODO(), nil)
	assert.Nil(t, err)
	assert.Equal(t, "dummy", res)
}
