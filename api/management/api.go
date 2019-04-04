package management_api

type UserRepresentation struct {
	Id            *string `json:"id,omitempty"`
	Username      *string `json:"username,omitempty"`
	Email         *string `json:"email,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
	EmailVerified *bool   `json:"emailVerified,omitempty"`
	FirstName     *string `json:"firstName,omitempty"`
	LastName      *string `json:"lastName,omitempty"`
	MobilePhone   *string `json:"mobilePhone,omitempty"`
	Label         *string `json:"label,omitempty"`
	Gender        *string `json:"gender,omitempty"`
	BirthDate     *string `json:"birthDate,omitempty"`
	Groups         *[]string `json:"group,omitempty"`
}

type RealmRepresentation struct {
	Id              *string `json:"id,omitempty"`
	KeycloakVersion *string `json:"keycloakVersion,omitempty"`
	Realm           *string `json:"realm,omitempty"`
	DisplayName     *string `json:"displayName,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

type ClientRepresentation struct {
	Id          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
	BaseUrl     *string `json:"baseUrl,omitempty"`
	ClientId    *string `json:"clientId,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

type RoleRepresentation struct {
	ClientRole  *bool   `json:"clientRole,omitempty"`
	Composite   *bool   `json:"composite,omitempty"`
	ContainerId *string `json:"containerId,omitempty"`
	Description *string `json:"description,omitempty"`
	Id          *string `json:"id,omitempty"`
	Name        *string `json:"name,omitempty"`
}

type PasswordRepresentation struct {
	Value *string `json:"value,omitempty"`
}
