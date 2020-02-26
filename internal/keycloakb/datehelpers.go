package keycloakb

import (
	"regexp"
	"strconv"
	"time"

	errorhandler "github.com/cloudtrust/common-service/errors"
	stats_api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
)

// ConvertMinutesShift converts a string describing a timezone shift to a numeric value
func ConvertMinutesShift(value string) (int, error) {
	if ok, err := regexp.MatchString(stats_api.RegExpTimeshift, value); err != nil || !ok {
		return 0, errorhandler.CreateInvalidQueryParameterError(msg.Timeshift)
	}
	res, _ := strconv.Atoi(value)
	return res, nil
}

// NextHour returns a time.Time value of the provided time rounded to the next hour of the associated locale
func NextHour(ref time.Time) time.Time {
	return time.Date(ref.Year(), ref.Month(), ref.Day(), ref.Hour(), 0, 0, 0, ref.Location()).Add(time.Hour).UTC()
}

// NextDay returns a time.Time value of the provided time rounded to the next month of the associated locale
func NextDay(ref time.Time) time.Time {
	return time.Date(ref.Year(), ref.Month(), ref.Day(), 0, 0, 0, 0, ref.Location()).Add(time.Duration(24) * time.Hour).UTC()
}

// ThisMonth returns a time.Time value of the provided time rounded to the beginning of the current month of the associated locale
func ThisMonth(ref time.Time) time.Time {
	return time.Date(ref.Year(), ref.Month(), 1, 0, 0, 0, 0, ref.Location()).UTC()
}

// NextMonth returns a time.Time value of the provided time rounded to the next month of the associated locale
func NextMonth(ref time.Time) time.Time {
	var year = ref.Year()
	var month = ref.Month()
	if month == time.December {
		month = time.January
		year++
	} else {
		month = time.Month(int(month) + 1)
	}
	return time.Date(year, month, 1, 0, 0, 0, 0, ref.Location()).UTC()
}
