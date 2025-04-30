package profile

import (
	// Import used to embed default-profile.json file in local variable
	_ "embed"
	"encoding/json"

	kc "github.com/cloudtrust/keycloak-client/v2"
)

//go:embed default-profile.json
var defaultUserProfile string

// DefaultProfile returns a default profile
func DefaultProfile(realmName string) (kc.UserProfileRepresentation, error) {
	var res kc.UserProfileRepresentation
	var err = json.Unmarshal([]byte(defaultUserProfile), &res)
	return res, err
}
