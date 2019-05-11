package event

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/stretchr/testify/assert"
)

type storer struct {
	t *testing.T
	m map[string]string
}

func newStorer(t *testing.T) *storer {
	return &storer{
		t: t,
		m: nil,
	}
}

func (s *storer) Store(_ context.Context, m map[string]string) error {
	s.m = m
	return nil
}

func (s *storer) assertLength(expectedLength int) {
	assert.Equal(s.t, expectedLength, len(s.m))
}

func (s *storer) assertContainsKey(key string) {
	_, ok := s.m[key]
	assert.True(s.t, ok)
}

func (s *storer) assertContains(key, value string) {
	assert.Equal(s.t, value, s.m[key])
}

func TestReportEvent(t *testing.T) {
	apiCall := "MY_API"
	origin := "MY_ORIGIN"
	key1 := "KEY1"
	value1 := "VALUE1"
	key2 := "KEY2"
	value2 := "VALUE2"
	agentUsername := "username"
	agentRealmName := "realname"

	s := newStorer(t)
	ctx := context.Background()
	ctx = context.WithValue(ctx, cs.CtContextUsername, agentUsername)
	ctx = context.WithValue(ctx, cs.CtContextRealm, agentRealmName)

	ReportEvent(ctx, s, apiCall, origin, key1, value1, key2, value2)
	s.assertLength(7)
	s.assertContains("ct_event_type", apiCall)
	s.assertContains("origin", origin)
	s.assertContainsKey("audit_time")
	s.assertContains(key1, value1)
	s.assertContains(key2, value2)
	s.assertContains("agent_username", agentUsername)
	s.assertContains("agent_realm_name", agentRealmName)
}
