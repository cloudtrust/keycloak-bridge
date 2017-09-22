package monitoring

import (
	"net/http"
	"fmt"
)
func MakeVersion(version string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("Application version : %s\n", version)))
	}
}