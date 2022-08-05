package validation

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,TokenProvider=TokenProvider,EventsDBModule=EventsDBModule,UsersDetailsDBModule=UsersDetailsDBModule,ArchiveDBModule=ArchiveDBModule,ConfigurationDBModule=ConfigurationDBModule,AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/pkg/validation Component,KeycloakClient,TokenProvider,EventsDBModule,UsersDetailsDBModule,ArchiveDBModule,ConfigurationDBModule,AccreditationsServiceClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/v2/security AuthorizationManager

func ptr(value string) *string {
	return &value
}
