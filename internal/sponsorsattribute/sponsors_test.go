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

func TestGetSponsor(t *testing.T) {
	logger := log.NewNopLogger()
	ctx := context.TODO()
	attr := New(ctx, new("{-"), logger)

	attr.SetSponsors([]string{"accred1"}, "sponsor1")
	sponsor, ok := attr.GetSponsor("accred1")
	assert.True(t, ok)
	assert.Equal(t, "sponsor1", sponsor)

	sponsor, ok = attr.GetSponsor("accred2")
	assert.False(t, ok)
	assert.Equal(t, "", sponsor)
}
