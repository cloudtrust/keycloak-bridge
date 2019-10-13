package dto

// RealmConfiguration struct
type RealmConfiguration struct {
	DefaultClientID                 *string `json:"default_client_id,omitempty"`
	DefaultRedirectURI              *string `json:"default_redirect_uri,omitempty"`
	APISelfAuthenticatorMgmtEnabled *bool   `json:"api_self_authenticator_mgmt_enabled"`
	APISelfPasswordChangeEnabled    *bool   `json:"api_self_password_change_enabled"`
	APISelfMailEditionEnabled       *bool   `json:"api_self_mail_edition_enabled"`
	APISelfDeleteAccountEnabled     *bool   `json:"api_self_delete_account_enabled"`
	UISelfAuthenticatorMgmtEnabled  *bool   `json:"ui_self_authenticator_mgmt_enabled"`
	UISelfPasswordChangeEnabled     *bool   `json:"ui_self_password_change_enabled"`
	UISelfMailEditionEnabled        *bool   `json:"ui_self_mail_edition_enabled"`
	UISelfDeleteAccountEnabled      *bool   `json:"ui_self_delete_account_enabled"`
}
