package keycloakb

import (
	"encoding/json"
	"errors"
	"time"
)

// PendingChecks interface
type PendingChecks interface {
	AddPendingCheck(nature string)
	RemovePendingCheck(nature string)
	ToAttribute() *string
	ToCheckNames() *[]string
}

type pendingChecks struct {
	checks map[string]int64
}

// Exportable values
var (
	ErrCantUnmarshalPendingCheck = errors.New("can't unmarshal pending check value")
)

// AddPendingCheck adds a pending check
func AddPendingCheck(value *string, nature string) (*string, error) {
	var pc, err = NewPendingChecks(value)
	if err != nil && err != ErrCantUnmarshalPendingCheck {
		return nil, err
	}
	pc.AddPendingCheck(nature)
	return pc.ToAttribute(), err
}

// RemovePendingCheck removes a pending check
func RemovePendingCheck(value *string, nature string) (*string, error) {
	var pc, err = NewPendingChecks(value)
	if err != nil && err != ErrCantUnmarshalPendingCheck {
		return nil, err
	}
	pc.RemovePendingCheck(nature)
	return pc.ToAttribute(), err
}

// GetPendingChecks get pending checks
func GetPendingChecks(value *string) *[]string {
	var pc, err = NewPendingChecks(value)
	if err != nil && err != ErrCantUnmarshalPendingCheck {
		return nil
	}
	return pc.ToCheckNames()
}

// NewPendingChecks creates a PendingChecks value
func NewPendingChecks(value *string) (PendingChecks, error) {
	var checks map[string]int64
	var err error
	if value != nil {
		if errUnmarshal := json.Unmarshal([]byte(*value), &checks); errUnmarshal != nil {
			err = ErrCantUnmarshalPendingCheck
		}
	}
	if checks == nil {
		checks = map[string]int64{}
	}

	return &pendingChecks{
		checks: checks,
	}, err
}

func (pc *pendingChecks) AddPendingCheck(nature string) {
	pc.checks[nature] = time.Now().UnixNano() / 1000000
}

func (pc *pendingChecks) RemovePendingCheck(nature string) {
	delete(pc.checks, nature)
}

func (pc *pendingChecks) ToAttribute() *string {
	if len(pc.checks) == 0 {
		return nil
	}
	var bytes, _ = json.Marshal(pc.checks)
	var attribute = string(bytes)
	return &attribute
}

func (pc *pendingChecks) ToCheckNames() *[]string {
	var res []string
	for check := range pc.checks {
		res = append(res, check)
	}
	if len(res) == 0 {
		return nil
	}
	return &res
}
