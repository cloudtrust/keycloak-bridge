package keycloakb

import (
	"encoding/json"
	"time"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

var (
	dateLayout = constants.SupportedDateLayouts[0]
)

const (
	// CredsIDNow identifies the condition for IDNow service
	CredsIDNow = configuration.CheckKeyIDNow
	// CredsPhysical identifies the condition for physical identification
	CredsPhysical = configuration.CheckKeyPhysical
)

// AccredsKeycloakClient is the minimum Keycloak client interface for accreditations
type AccredsKeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
}

// AccreditationRepresentation is a representation of accreditations
type AccreditationRepresentation struct {
	Type           *string `json:"type,omitempty"`
	CreationMillis *int64  `json:"creationMillis,omitempty"`
	ExpiryDate     *string `json:"expiryDate,omitempty"`
	Revoked        *bool   `json:"revoked,omitempty"`
}

// RevokeAccreditations revokes active accreditations of the given user
func RevokeAccreditations(kcUser *kc.UserRepresentation) bool {
	var kcAccreds = kcUser.GetFieldValues(fields.Accreditations)
	if len(kcAccreds) > 0 {
		var accredProcessor, _ = NewAccreditationsProcessor(kcAccreds)
		if accredProcessor.RevokeAll() {
			kcUser.SetFieldValues(fields.Accreditations, accredProcessor.ToKeycloak())
			return true
		}
	}
	return false
}

// AccreditationsProcessor interface
type AccreditationsProcessor interface {
	HasActiveAccreditations() bool
	AddAccreditation(creationDate time.Time, name string, validity string)
	RevokeAll() bool
	RevokeTypes(accreditationsTypes []string) bool
	ToKeycloak() []string
}

type accredsProcessor struct {
	accreditations map[string][]AccreditationRepresentation
}

// NewAccreditationsProcessor creates an accreditations processor
func NewAccreditationsProcessor(accreditations []string) (AccreditationsProcessor, error) {
	var res = accredsProcessor{accreditations: make(map[string][]AccreditationRepresentation)}
	var bestEffortError error

	for _, accred := range accreditations {
		var newAccred AccreditationRepresentation
		if err := json.Unmarshal([]byte(accred), &newAccred); err != nil {
			// Will return an error but try to go on processing. It is up to the caller to treat the error or to ignore it and process the valid accreditations
			bestEffortError = err
			continue
		}
		if slice, ok := res.accreditations[*newAccred.Type]; ok {
			slice = append(slice, newAccred)
			res.accreditations[*newAccred.Type] = slice
		} else {
			res.accreditations[*newAccred.Type] = []AccreditationRepresentation{newAccred}
		}
	}

	return &res, bestEffortError
}

func (ap *accredsProcessor) HasActiveAccreditations() bool {
	for _, slice := range ap.accreditations {
		for _, oldAccred := range slice {
			if ap.isActive(oldAccred) {
				return true
			}
		}
	}
	return false
}

func (ap *accredsProcessor) AddAccreditation(creationDate time.Time, name string, validity string) {
	creationMillis := creationDate.UnixNano() / int64(time.Millisecond)
	expiryDate := validation.AddLargeDuration(creationDate, validity).UTC().Format(dateLayout)

	var newAccred = AccreditationRepresentation{
		Type:           &name,
		CreationMillis: &creationMillis,
		ExpiryDate:     &expiryDate,
	}
	var newAccredSlice []AccreditationRepresentation
	var bTrue = true
	if slice, ok := ap.accreditations[name]; ok {
		for _, oldAccred := range slice {
			if ap.isActive(oldAccred) {
				oldAccred.Revoked = &bTrue
			}
			newAccredSlice = append(newAccredSlice, oldAccred)
		}
	}
	ap.accreditations[name] = append(newAccredSlice, newAccred)
}

func (ap *accredsProcessor) RevokeAll() bool {
	var res = false
	for k := range ap.accreditations {
		if ap.RevokeType(k) {
			res = true
		}
	}
	return res
}

func (ap *accredsProcessor) RevokeType(accreditationsType string) bool {
	var res = false
	if slice, ok := ap.accreditations[accreditationsType]; ok {
		var newSlice []AccreditationRepresentation
		var bTrue = true
		for _, accred := range slice {
			if ap.isActive(accred) {
				accred.Revoked = &bTrue
				res = true
			}
			newSlice = append(newSlice, accred)
		}
		ap.accreditations[accreditationsType] = newSlice
	}
	return res
}

func (ap *accredsProcessor) RevokeTypes(accreditationsTypes []string) bool {
	var res = false
	for _, accredType := range accreditationsTypes {
		if ap.RevokeType(accredType) {
			res = true
		}
	}
	return res
}

func (ap *accredsProcessor) isActive(accred AccreditationRepresentation) bool {
	if accred.Revoked == nil || !*accred.Revoked {
		var today = time.Now()
		if expiry, err := time.Parse(dateLayout, *accred.ExpiryDate); err == nil && today.Before(expiry) {
			return true
		}
	}
	return false
}

func (ap *accredsProcessor) ToKeycloak() []string {
	var res []string
	for _, accredSlice := range ap.accreditations {
		for _, accred := range accredSlice {
			var bytes, _ = json.Marshal(accred)
			res = append(res, string(bytes))
		}
	}
	return res
}
