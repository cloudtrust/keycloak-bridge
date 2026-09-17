package sponsorsattribute

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/stretchr/testify/assert"
)

func TestSponsorsAttributeToString(t *testing.T) {
	logger := log.NewNopLogger()
	ctx := context.TODO()
	attr := New(ctx, new("{-"), logger)

	attr.SetSponsors(nil, "sponsor1")
	assert.Equal(t, `{}`, attr.ToString(ctx))

	attr.SetSponsors([]string{"accred2", "accred1"}, "sponsor1")
	assert.Equal(t, `{"accred1":"sponsor1","accred2":"sponsor1"}`, attr.ToString(ctx))
}
