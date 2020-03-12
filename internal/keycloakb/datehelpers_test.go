package keycloakb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	locSwitzerland = time.FixedZone("Swiss", 60*60)
	locIndia       = time.FixedZone("India", 270*60)
	locCookIsland  = time.FixedZone("Cook island", -600*60)
)

func TestConvertMinutesShift(t *testing.T) {
	_, err := ConvertMinutesShift("60")
	assert.NotNil(t, err)

	_, err = ConvertMinutesShift(" +90 ")
	assert.NotNil(t, err)

	value, _ := ConvertMinutesShift("+90")
	assert.Equal(t, 90, value)

	value, _ = ConvertMinutesShift("-270")
	assert.Equal(t, -270, value)
}

func TestNextHour(t *testing.T) {
	reference := time.Date(2020, time.January, 15, 14, 28, 7, 153, time.UTC)
	nextHourUTC := time.Date(2020, time.January, 15, 15, 0, 0, 0, time.UTC)
	nextHourUTCIndia := time.Date(2020, time.January, 15, 14, 30, 0, 0, time.UTC)

	assert.Equal(t, nextHourUTC, NextHour(reference))
	assert.Equal(t, nextHourUTC, NextHour(reference.In(locSwitzerland)))
	assert.Equal(t, nextHourUTCIndia, NextHour(reference.In(locIndia)))

	reference = time.Date(2020, time.January, 15, 14, 48, 7, 153, time.UTC)
	nextHourUTC = time.Date(2020, time.January, 15, 15, 0, 0, 0, time.UTC)
	nextHourUTCIndia = time.Date(2020, time.January, 15, 15, 30, 0, 0, time.UTC)

	assert.Equal(t, nextHourUTC, NextHour(reference))
	assert.Equal(t, nextHourUTC, NextHour(reference.In(locSwitzerland)))
	assert.Equal(t, nextHourUTCIndia, NextHour(reference.In(locIndia)))
}

func TestNextDay(t *testing.T) {
	reference := time.Date(2020, time.January, 15, 22, 48, 7, 153, time.UTC)
	nextDayUTC := time.Date(2020, time.January, 16, 0, 0, 0, 0, time.UTC)
	nextDaySwitzerland := time.Date(2020, time.January, 15, 23, 0, 0, 0, time.UTC)
	nextDayIndia := time.Date(2020, time.January, 16, 19, 30, 0, 0, time.UTC)
	nextDayCookIsland := time.Date(2020, time.January, 16, 10, 0, 0, 0, time.UTC)

	assert.Equal(t, nextDayUTC, NextDay(reference))
	assert.Equal(t, nextDaySwitzerland, NextDay(reference.In(locSwitzerland)))
	assert.Equal(t, nextDayIndia, NextDay(reference.In(locIndia)))
	assert.Equal(t, nextDayCookIsland, NextDay(reference.In(locCookIsland)))

	reference = time.Date(2020, time.January, 15, 23, 18, 7, 153, time.UTC)
	nextDayUTC = time.Date(2020, time.January, 16, 0, 0, 0, 0, time.UTC)
	nextDaySwitzerland = time.Date(2020, time.January, 16, 23, 0, 0, 0, time.UTC)
	nextDayIndia = time.Date(2020, time.January, 16, 19, 30, 0, 0, time.UTC)

	assert.Equal(t, nextDayUTC, NextDay(reference))
	assert.Equal(t, nextDaySwitzerland, NextDay(reference.In(locSwitzerland)))
	assert.Equal(t, nextDayIndia, NextDay(reference.In(locIndia)))
}

func TestThisMonth(t *testing.T) {
	reference := time.Date(2020, time.December, 1, 22, 48, 7, 153, time.UTC)

	assert.Equal(t, time.Date(2020, time.December, 1, 0, 0, 0, 0, time.UTC), ThisMonth(reference))
	assert.Equal(t, time.Date(2020, time.November, 30, 23, 0, 0, 0, time.UTC), ThisMonth(reference.In(locSwitzerland)))
	assert.Equal(t, time.Date(2020, time.November, 30, 19, 30, 0, 0, time.UTC), ThisMonth(reference.In(locIndia)))
	assert.Equal(t, time.Date(2020, time.December, 1, 10, 0, 0, 0, time.UTC), ThisMonth(reference.In(locCookIsland)))

	reference = time.Date(2020, time.December, 1, 3, 18, 7, 153, time.UTC)

	assert.Equal(t, time.Date(2020, time.December, 1, 0, 0, 0, 0, time.UTC), ThisMonth(reference))
	assert.Equal(t, time.Date(2020, time.November, 30, 23, 0, 0, 0, time.UTC), ThisMonth(reference.In(locSwitzerland)))
	assert.Equal(t, time.Date(2020, time.November, 30, 19, 30, 0, 0, time.UTC), ThisMonth(reference.In(locIndia)))
	assert.Equal(t, time.Date(2020, time.November, 1, 10, 0, 0, 0, time.UTC), ThisMonth(reference.In(locCookIsland)))
}

func TestNextMonth(t *testing.T) {
	reference := time.Date(2020, time.January, 15, 22, 48, 7, 153, time.UTC)
	nextMonthUTC := time.Date(2020, time.February, 1, 0, 0, 0, 0, time.UTC)
	nextMonthSwitzerland := time.Date(2020, time.January, 31, 23, 0, 0, 0, time.UTC)
	nextMonthIndia := time.Date(2020, time.January, 31, 19, 30, 0, 0, time.UTC)
	nextMonthCookIsland := time.Date(2020, time.February, 1, 10, 0, 0, 0, time.UTC)

	assert.Equal(t, nextMonthUTC, NextMonth(reference))
	assert.Equal(t, nextMonthSwitzerland, NextMonth(reference.In(locSwitzerland)))
	assert.Equal(t, nextMonthIndia, NextMonth(reference.In(locIndia)))
	assert.Equal(t, nextMonthCookIsland, NextMonth(reference.In(locCookIsland)))

	reference = time.Date(2020, time.December, 31, 23, 48, 7, 153, time.UTC)
	nextMonthUTC = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	nextMonthSwitzerland = time.Date(2021, time.January, 31, 23, 0, 0, 0, time.UTC)
	nextMonthIndia = time.Date(2021, time.January, 31, 19, 30, 0, 0, time.UTC)
	nextMonthCookIsland = time.Date(2021, time.January, 1, 10, 0, 0, 0, time.UTC)

	assert.Equal(t, nextMonthUTC, NextMonth(reference))
	assert.Equal(t, nextMonthSwitzerland, NextMonth(reference.In(locSwitzerland)))
	assert.Equal(t, nextMonthIndia, NextMonth(reference.In(locIndia)))
	assert.Equal(t, nextMonthCookIsland, NextMonth(reference.In(locCookIsland)))
}

func TestIsDateInThePast(t *testing.T) {
	t.Run("Nil value", func(t *testing.T) {
		assert.Nil(t, IsDateInThePast(nil))
	})
	t.Run("Invalid value", func(t *testing.T) {
		var date = "32.13.2049"
		assert.Nil(t, IsDateInThePast(&date))
	})
	t.Run("Date in the past", func(t *testing.T) {
		var date = "01.01.2010"
		assert.True(t, *IsDateInThePast(&date))
	})
	t.Run("Date in the future", func(t *testing.T) {
		var date = "31.12.2100"
		assert.False(t, *IsDateInThePast(&date))
	})
}
