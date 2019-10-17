package dto

// RealmConfiguration struct
type RealmConfiguration struct {
	DefaultClientID                     *string `json:"default_client_id"`
	DefaultRedirectURI                  *string `json:"default_redirect_uri"`
	APISelfAuthenticatorDeletionEnabled *bool   `json:"api_self_authenticator_deletion_enabled"`
	APISelfPasswordChangeEnabled        *bool   `json:"api_self_password_change_enabled"`
	APISelfMailEditingEnabled           *bool   `json:"api_self_mail_editing_enabled"`
	APISelfAccountDeletionEnabled       *bool   `json:"api_self_account_deletion_enabled"`
	ShowAuthenticatorsTab               *bool   `json:"show_authenticators_tab"`
	ShowPasswordTab                     *bool   `json:"show_password_tab"`
	ShowMailEditing                     *bool   `json:"show_mail_editing"`
	ShowAccountDeletionButton           *bool   `json:"show_account_deletion_button"`
}
