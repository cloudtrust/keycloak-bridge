package business

import (
	errorhandler "github.com/cloudtrust/common-service/errors"
)

// GlnSearchResult is the result of a GLN lookup.
// It includes effective result field and an error field in order to be passed through a channel in a single operation
type GlnSearchResult struct {
	Persons []GlnPerson
	Error   error
}

// GlnPerson describes a person found by his/her GLN number
type GlnPerson struct {
	Active     *bool
	Number     *string
	FirstName  *string
	LastName   *string
	Canton     *string
	ZipCode    *string
	City       *string
	Country    *string
	Profession *string
}

// Error constants
var (
	ErrGLNNotFound         error
	ErrGLNDoesNotMatch     error
	ErrGLNCantParse        error
	ErrGLNNoLookupProvider error
)

// GlnLookupProvider interface
type GlnLookupProvider interface {
	Lookup(gln string) GlnSearchResult
}

// GlnVerifier interface
type GlnVerifier interface {
	ValidateGLN(firstName, lastName, gln string) error
}

type glnVerifier struct {
	providers []GlnLookupProvider
}

func initGln() {
	if ErrGLNNotFound == nil {
		ErrGLNNotFound = errorhandler.CreateBadRequestError("glnNotFound")
		ErrGLNDoesNotMatch = errorhandler.CreateBadRequestError("glnDoesNotMatch")
		ErrGLNCantParse = errorhandler.CreateInternalServerError("glnCantParseXML")
		ErrGLNNoLookupProvider = errorhandler.CreateInternalServerError("glnNoLookupProvided")
	}
}

// NewGlnVerifier creates a GLN verifier using given GLN lookup providers
func NewGlnVerifier(providers ...GlnLookupProvider) GlnVerifier {
	initGln()
	return &glnVerifier{
		providers: providers,
	}
}

func (v *glnVerifier) ValidateGLN(firstName, lastName, gln string) error {
	var size = len(v.providers)
	if size == 0 {
		return ErrGLNNoLookupProvider
	}

	resultsChan := make(chan GlnSearchResult, size)
	defer close(resultsChan)

	for _, provider := range v.providers {
		go func(glnLookup GlnLookupProvider) {
			var result = glnLookup.Lookup(gln)
			select {
			case <-resultsChan:
				return
			default:
				resultsChan <- result
			}
		}(provider)
	}
	var defaultError = ErrGLNNotFound
	for i := 0; i < size; i++ {
		var details = <-resultsChan
		if details.Error == nil {
			for _, person := range details.Persons {
				if v.compare(person, firstName, lastName, gln) {
					return nil
				}
			}
			return ErrGLNDoesNotMatch
		} else if details.Error != ErrGLNNotFound {
			defaultError = details.Error
		}
	}
	return defaultError
}

func (v *glnVerifier) compare(glnPerson GlnPerson, firstName, lastName, gln string) bool {
	return glnPerson.Number != nil && glnPerson.FirstName != nil && glnPerson.LastName != nil &&
		gln == *glnPerson.Number && firstName == *glnPerson.FirstName && lastName == *glnPerson.LastName
}
