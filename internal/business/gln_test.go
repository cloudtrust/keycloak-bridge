package business

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type mockLookup struct {
	id      int
	glnList map[string]GlnSearchResult
	delay   time.Duration
}

func ptr(value string) *string {
	return &value
}

func NewMockLookup(id int, delay time.Duration) *mockLookup {
	return &mockLookup{
		id:      id,
		glnList: make(map[string]GlnSearchResult),
		delay:   delay,
	}
}

func (m *mockLookup) Add(gln string) {
	m.glnList[gln] = GlnSearchResult{
		Persons: []GlnPerson{
			{Number: ptr(gln), FirstName: ptr("Tom"), LastName: ptr("Thomaser")},
			{Number: ptr(gln), FirstName: ptr("Nana"), LastName: ptr("Dubouchon")},
		},
		Error: nil,
	}
}

func (m *mockLookup) Lookup(gln string) GlnSearchResult {
	time.Sleep(m.delay)
	if value, ok := m.glnList[gln]; ok {
		return value
	}
	return GlnSearchResult{Error: ErrGLNNotFound}
}

func TestGln(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var gln = "111111111"
	var mockProviders = []GlnLookupProvider{NewMockLookup(1, time.Millisecond*100), NewMockLookup(2, time.Millisecond*10), NewMockLookup(3, time.Millisecond*10)}
	mockProviders[0].(*mockLookup).Add(gln)

	var glnVerifier = NewGlnVerifier(mockProviders...)

	t.Run("Unknown GLN", func(t *testing.T) {
		var err = glnVerifier.ValidateGLN("Tom", "Tom", "123456789")
		assert.Equal(t, ErrGLNNotFound, err)
	})
	t.Run("Does not match", func(t *testing.T) {
		var err = glnVerifier.ValidateGLN("Nana", "Dubidon", gln)
		assert.Equal(t, ErrGLNDoesNotMatch, err)
	})
	t.Run("Matching GLN", func(t *testing.T) {
		var err = glnVerifier.ValidateGLN("Nana", "Dubouchon", gln)
		assert.Nil(t, err)
	})
}
