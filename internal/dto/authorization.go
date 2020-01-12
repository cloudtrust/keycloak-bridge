package dto

// AuthorizationConfiguration struct
type AuthorizationConfiguration struct {
	RealmID       *string `json:"realm_id"`
	GroupName     *string `json:"group_name"`
	Configuration *string `json:"configuration"`
}
