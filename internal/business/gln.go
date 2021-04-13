package business

import (
	"errors"

	errorhandler "github.com/cloudtrust/common-service/errors"
)

type GlnDetails struct {
	Active     *bool
	Number     *string
	FirstName  *string
	LastName   *string
	Canton     *string
	ZipCode    *string
	City       *string
	Country    *string
	Profession *string
	Error      error
}

var (
	ErrGLNNoDecision = errors.New("nodecision")
)

type GlnLookupProvider interface {
	Lookup(gln string) GlnDetails
}

type GlnVerifier interface {
	ValidateGLN(firstName, lastName, gln string) error
}

type glnVerifier struct {
	providers []GlnLookupProvider
}

func NewGlnVerifier(providers ...GlnLookupProvider) GlnVerifier {
	return &glnVerifier{
		providers: providers,
	}
}

func (v *glnVerifier) ValidateGLN(firstName, lastName, gln string) error {
	if gln == "7601000001726" {
		// Hard coded value for development
		return nil
	}
	var size = len(v.providers)
	if size == 0 {
		return errorhandler.CreateInternalServerError("noGLNLookupProvided")
	}

	resultsChan := make(chan GlnDetails)
	defer close(resultsChan)

	for _, provider := range v.providers {
		go func(glnLookup GlnLookupProvider) {
			resultsChan <- glnLookup.Lookup(gln)
		}(provider)
	}
	for i := 0; i < size; i++ {
		var details = <-resultsChan
		if details.Error == nil {
			if v.compare(details, firstName, lastName, gln) {
				return nil
			}
			return errorhandler.CreateBadRequestError("glnDoesNotMatch")
		}
	}
	return errorhandler.CreateBadRequestError("invalidParameter.gln")
}

func (v *glnVerifier) compare(glnDetails GlnDetails, firstName, lastName, gln string) bool {
	if glnDetails.Number == nil || glnDetails.FirstName == nil || glnDetails.LastName == nil {
		return false
	}
	return gln == *glnDetails.Number && firstName == *glnDetails.FirstName && lastName == *glnDetails.LastName
}
