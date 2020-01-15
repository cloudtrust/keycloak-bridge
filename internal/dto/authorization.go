package dto

// Authorization struct
type Authorization struct {
	RealmID       *string `json:"realm_id"`
	GroupID       *string `json:"group_id"`
	Action        *string `json:"action"`
	TargetRealmID *string `json:"target_realm_id,omitempty"`
	TargetGroupID *string `json:"target_group_id,omitempty"`
}
