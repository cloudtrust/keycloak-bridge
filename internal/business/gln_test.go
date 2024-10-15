package business

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
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

func (m *mockLookup) AddPerson(gln string, firstName *string, lastName *string) {
	m.glnList[gln] = GlnSearchResult{
		Persons: []GlnPerson{
			{Number: ptr(gln), FirstName: firstName, LastName: lastName},
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	anError := errors.New("an error")
	gln := "111111111"
	mockProviders := []GlnLookupProvider{
		newMockLookup(1, time.Millisecond*100, nil), newMockLookup(2, time.Millisecond*10, nil),
		newMockLookup(3, time.Millisecond*10, nil),
	}
	mockProviders[0].(*mockLookup).Add(gln)

	glnNilFirstName := "888888888"
	glnNilLastName := "333333333"
	mockProviders[0].(*mockLookup).AddPerson(glnNilFirstName, nil, ptr("NameRandom1"))
	mockProviders[0].(*mockLookup).AddPerson(glnNilLastName, ptr("NameRandom2"), nil)

	glnVerifier := NewGlnVerifier()
	t.Run("No GLN Lookup", func(t *testing.T) {
		err := glnVerifier.ValidateGLN("Tom", "Tom", "123456789")
		assert.Equal(t, ErrGLNNoLookupProvider, err)
	})

	glnVerifier = NewGlnVerifier(mockProviders...)

	t.Run("Unknown GLN", func(t *testing.T) {
		err := glnVerifier.ValidateGLN("Tom", "Tom", "123456789")
		assert.Equal(t, ErrGLNNotFound, err)
	})
	t.Run("Does not match", func(t *testing.T) {
		err := glnVerifier.ValidateGLN("Nana", "Dubidon", gln)
		assert.Equal(t, ErrGLNDoesNotMatch, err)
	})
	t.Run("Matching GLN", func(t *testing.T) {
		err := glnVerifier.ValidateGLN("Nana", "Dubouchon", gln)
		assert.Nil(t, err)
	})

	t.Run("Matching GLN, firstname nil", func(t *testing.T) {
		err := glnVerifier.ValidateGLN("", "NameRandom1", glnNilFirstName)
		assert.Nil(t, err)
	})

	t.Run("Matching GLN, lastname nil", func(t *testing.T) {
		err := glnVerifier.ValidateGLN("NameRandom2", "", glnNilLastName)
		assert.Nil(t, err)
	})

	t.Run("Lookup provider fails", func(t *testing.T) {
		mockProviders = []GlnLookupProvider{newMockLookup(1, time.Millisecond, anError), newMockLookup(1, time.Millisecond*10, nil)}
		glnVerifier = NewGlnVerifier(mockProviders...)
		err := glnVerifier.ValidateGLN("Tom", "Tom", "123456789")
		assert.Equal(t, anError, err)
	})
	t.Run("Positive response comes much faster than other responses", func(t *testing.T) {
		mockProviders = []GlnLookupProvider{newMockLookup(1, time.Millisecond*100, anError), newMockLookup(1, time.Millisecond, nil)}
		mockProviders[1].(*mockLookup).Add(gln)
		glnVerifier = NewGlnVerifier(mockProviders...)
		err := glnVerifier.ValidateGLN("Tom", "Thomaser", gln)
		assert.Nil(t, err)
		// ensure there is no panic
		time.Sleep(time.Second)
	})
}

func TestCompare(t *testing.T) {
	verifier := &glnVerifier{}
	person := GlnPerson{Number: ptr("number"), FirstName: ptr("firstname"), LastName: ptr("lastname")}
	assert.False(t, verifier.compare(person, "firstname", "lastname", "another"))
	assert.False(t, verifier.compare(person, "firstname", "another", "number"))
	assert.False(t, verifier.compare(person, "another", "lastname", "number"))
	assert.True(t, verifier.compare(person, "firstname", "lastname", "number"))

	person.Number = nil
	assert.False(t, verifier.compare(person, "firstname", "lastname", ""))

	person = GlnPerson{Number: ptr("number"), FirstName: ptr("firstname"), LastName: nil}
	assert.True(t, verifier.compare(person, "firstname", "", "number"))

	person = GlnPerson{Number: ptr("number"), FirstName: nil, LastName: ptr("lastname")}
	assert.True(t, verifier.compare(person, "", "lastname", "number"))

	person = GlnPerson{Number: ptr(" number "), FirstName: ptr(" firstname "), LastName: ptr(" lastname ")}
	assert.True(t, verifier.compare(person, "  firstname", "lastname  ", "  number  "))
}
