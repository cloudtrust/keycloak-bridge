package keycloakb

import (
	"fmt"
	"net/http"
)

// HTTPError can be returned by the API endpoints
type HTTPError struct {
	Status  int
	Message string
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("%d %s", e.Status, e.Message)
}

// CreateMissingParameterError creates a HTTPResponse for an error relative to a missing mandatory parameter
func CreateMissingParameterError(name string) HTTPError {
	return HTTPError{
		Status:  http.StatusBadRequest,
		Message: fmt.Sprintf("Missing mandatory parameter %s", name),
	}
}
