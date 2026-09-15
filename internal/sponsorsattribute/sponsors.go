package sponsorsattribute

import (
	"context"
	"encoding/json"

	"github.com/cloudtrust/common-service/v2/log"
)

type SponsorsAttribute struct {
	value  map[string]string
	logger log.Logger
}

// New creates a new sponsorsAttribute instance, initializing it with the given JSON string value
func New(ctx context.Context, value *string, logger log.Logger) SponsorsAttribute {
	attr := SponsorsAttribute{
		value:  make(map[string]string),
		logger: logger,
	}
	if value != nil {
		if err := json.Unmarshal([]byte(*value), &attr.value); err != nil {
			logger.Error(ctx, "Failed to unmarshal sponsors attribute", "error", err, "value", *value)
		}
	}
	return attr
}

func (sa *SponsorsAttribute) SetSponsors(accreds []string, sponsors string) {
	for _, accred := range accreds {
		sa.value[accred] = sponsors
	}
}

func (sa *SponsorsAttribute) ToString(ctx context.Context) string {
	bytes, err := json.Marshal(sa.value)
	if err != nil {
		sa.logger.Error(ctx, "Failed to marshal sponsors attribute", "error", err)
		return ""
	}
	return string(bytes)
}
