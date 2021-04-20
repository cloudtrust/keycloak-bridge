package business

import (
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type mockLookup struct {
	id      int
	glnList map[string]GlnSearchResult
	delay   time.Duration
	err     error
}

func ptr(value string) *string {
	return &value
}

func newMockLookup(id int, delay time.Duration, err error) *mockLookup {
	return &mockLookup{
		id:      id,
		glnList: make(map[string]GlnSearchResult),
		delay:   delay,
		err:     err,
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
	if m.err != nil {
		return GlnSearchResult{Error: m.err}
	}
	if value, ok := m.glnList[gln]; ok {
		return value
	}
	return GlnSearchResult{Error: ErrGLNNotFound}
}

func TestGln(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var gln = "111111111"
	var mockProviders = []GlnLookupProvider{newMockLookup(1, time.Millisecond*100, nil), newMockLookup(2, time.Millisecond*10, nil),
		newMockLookup(3, time.Millisecond*10, nil)}
	mockProviders[0].(*mockLookup).Add(gln)

	var glnVerifier = NewGlnVerifier()
	t.Run("No GLN Lookup", func(t *testing.T) {
		var err = glnVerifier.ValidateGLN("Tom", "Tom", "123456789")
		assert.Equal(t, ErrGLNNoLookupProvider, err)
	})

	glnVerifier = NewGlnVerifier(mockProviders...)

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

	var anError = errors.New("an error")
	mockProviders = []GlnLookupProvider{newMockLookup(1, time.Millisecond, anError), newMockLookup(1, time.Millisecond*10, nil)}
	glnVerifier = NewGlnVerifier(mockProviders...)
	t.Run("Lookup provider fails", func(t *testing.T) {
		var err = glnVerifier.ValidateGLN("Tom", "Tom", "123456789")
		assert.Equal(t, anError, err)
	})
}
