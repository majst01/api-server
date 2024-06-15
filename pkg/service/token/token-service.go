package token

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/service/method"
	tokenutil "github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"github.com/metal-stack/api/go/permissions"
	"github.com/metal-stack/metal-lib/pkg/pointer"
)

type Config struct {
	Log        *slog.Logger
	TokenStore tokenutil.TokenStore
	CertStore  certs.CertStore

	// AdminSubjects are the subjects for which the token service allows the creation of admin api tokens
	AdminSubjects []string

	// Issuer to sign the JWT Token with
	Issuer string
}

type tokenService struct {
	issuer             string
	adminSubjects      []string
	tokens             tokenutil.TokenStore
	certs              certs.CertStore
	log                *slog.Logger
	servicePermissions *permissions.ServicePermissions
}

type TokenService interface {
	apiv1connect.TokenServiceHandler
	// FIXME do we need these two Services ?
	CreateConsoleTokenWithoutPermissionCheck(ctx context.Context, subject string, rq *connect.Request[apiv1.TokenServiceCreateRequest]) (*connect.Response[apiv1.TokenServiceCreateResponse], error)
	CreateApiTokenWithoutPermissionCheck(ctx context.Context, rq *connect.Request[apiv1.TokenServiceCreateRequest]) (*connect.Response[apiv1.TokenServiceCreateResponse], error)
}

func New(c Config) TokenService {
	servicePermissions := permissions.GetServicePermissions()

	return &tokenService{
		tokens:             c.TokenStore,
		certs:              c.CertStore,
		issuer:             c.Issuer,
		log:                c.Log.WithGroup("tokenService"),
		servicePermissions: servicePermissions,
		adminSubjects:      c.AdminSubjects,
	}
}

// CreateConsoleTokenWithoutPermissionCheck is only called from the auth service during login through console
// No validation against requested roles and permissions is required and implemented here
func (t *tokenService) CreateConsoleTokenWithoutPermissionCheck(ctx context.Context, subject string, rq *connect.Request[apiv1.TokenServiceCreateRequest]) (*connect.Response[apiv1.TokenServiceCreateResponse], error) {
	t.log.Debug("create", "token", rq)
	req := rq.Msg

	expires := tokenutil.DefaultExpiration
	if req.Expires != nil {
		expires = req.Expires.AsDuration()
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to fetch signing certificate: %w", err))
	}

	secret, token, err := tokenutil.NewJWT(apiv1.TokenType_TOKEN_TYPE_CONSOLE, subject, t.issuer, expires, privateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to create console token: %w", err))
	}

	token.Permissions = req.Permissions
	token.ProjectRoles = req.ProjectRoles
	token.TenantRoles = req.TenantRoles

	err = t.tokens.Set(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TokenServiceCreateResponse{
		Token:  token,
		Secret: secret,
	}), nil
}

// CreateApiTokenWithoutPermissionCheck is only called from the api-server command line interface
// No validation against requested roles and permissions is required and implemented here
func (t *tokenService) CreateApiTokenWithoutPermissionCheck(ctx context.Context, rq *connect.Request[apiv1.TokenServiceCreateRequest]) (*connect.Response[apiv1.TokenServiceCreateResponse], error) {
	t.log.Debug("create", "token", rq)
	req := rq.Msg

	expires := tokenutil.DefaultExpiration
	if req.Expires != nil {
		expires = req.Expires.AsDuration()
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	secret, token, err := tokenutil.NewJWT(apiv1.TokenType_TOKEN_TYPE_API, "api-server-cli", t.issuer, expires, privateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	token.Description = req.Description
	token.Permissions = req.Permissions
	token.ProjectRoles = req.ProjectRoles
	token.TenantRoles = req.TenantRoles
	token.AdminRole = req.AdminRole

	err = t.tokens.Set(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TokenServiceCreateResponse{
		Token:  token,
		Secret: secret,
	}), nil
}

// Create implements TokenService.
// TODO User is actually not able to select the Roles because there is no API Endpoint to fetch them
func (t *tokenService) Create(ctx context.Context, rq *connect.Request[apiv1.TokenServiceCreateRequest]) (*connect.Response[apiv1.TokenServiceCreateResponse], error) {
	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}
	req := rq.Msg

	err := validateTokenCreate(token, req, t.servicePermissions, t.adminSubjects)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	secret, token, err := tokenutil.NewJWT(apiv1.TokenType_TOKEN_TYPE_API, token.GetUserId(), t.issuer, req.Expires.AsDuration(), privateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	token.Description = req.Description
	token.Permissions = req.Permissions
	token.ProjectRoles = req.ProjectRoles
	token.TenantRoles = req.TenantRoles
	token.AdminRole = req.AdminRole

	err = t.tokens.Set(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &apiv1.TokenServiceCreateResponse{
		Token:  token,
		Secret: secret,
	}

	return connect.NewResponse(resp), nil
}

// List implements TokenService.
func (t *tokenService) List(ctx context.Context, _ *connect.Request[apiv1.TokenServiceListRequest]) (*connect.Response[apiv1.TokenServiceListResponse], error) {
	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	tokens, err := t.tokens.List(ctx, token.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TokenServiceListResponse{
		Tokens: tokens,
	}), nil
}

// Revoke implements TokenService.
func (t *tokenService) Revoke(ctx context.Context, rq *connect.Request[apiv1.TokenServiceRevokeRequest]) (*connect.Response[apiv1.TokenServiceRevokeResponse], error) {
	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	err := t.tokens.Revoke(ctx, token.UserId, rq.Msg.Uuid)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TokenServiceRevokeResponse{}), nil
}

func validateTokenCreate(currentToken *apiv1.Token, req *apiv1.TokenServiceCreateRequest, servicePermissions *permissions.ServicePermissions, adminIDs []string) error {
	var (
		tokenPermissionsMap = method.PermissionsBySubject(currentToken)
		tokenProjectRoles   = currentToken.ProjectRoles
		tokenTenantRoles    = currentToken.TenantRoles

		requestedProjectRoles = req.ProjectRoles
		requestedTenantRoles  = req.TenantRoles
		requestedAdminRole    = req.AdminRole
		requestedPermissions  = req.Permissions
	)

	// First check all requested permissions are defined in servicePermissions

	// if token permissions are empty fill them from token roles
	// methods restrictions are inherited from the user role for every project
	if len(tokenPermissionsMap) == 0 {
		tokenPermissionsMap = method.AllowedMethodsFromRoles(servicePermissions, currentToken)
	}

	for _, reqSubjectPermission := range requestedPermissions {
		reqSubjectID := reqSubjectPermission.Subject
		// Check if the requested subject, e.g. project or organization can be accessed
		tokenProjectPermissions, ok := tokenPermissionsMap[reqSubjectID]
		if !ok {
			return fmt.Errorf("requested subject:%q access is not allowed", reqSubjectID)
		}

		for _, reqMethod := range reqSubjectPermission.Methods {
			// Check if the requested permissions are part of all available methods
			if !servicePermissions.Methods[reqMethod] {
				return fmt.Errorf("requested method:%q is not allowed", reqMethod)
			}

			// Check if the requested permissions are part of the token
			if !slices.Contains(tokenProjectPermissions.Methods, reqMethod) {
				return fmt.Errorf("requested method:%q is not allowed for subject:%q", reqMethod, reqSubjectID)
			}
		}
	}

	// derive if a user has admin privileges in case he belongs to a certain id, which was preconfigured in the deployment
	for _, subject := range adminIDs {
		if currentToken.UserId != subject {
			// we exclude invited members of an admin tenant
			continue
		}

		role, ok := currentToken.TenantRoles[subject]
		if !ok {
			continue
		}

		switch role {
		case apiv1.TenantRole_TENANT_ROLE_EDITOR, apiv1.TenantRole_TENANT_ROLE_OWNER:
			currentToken.AdminRole = pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR)
		case apiv1.TenantRole_TENANT_ROLE_VIEWER:
			currentToken.AdminRole = pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_VIEWER)
		case apiv1.TenantRole_TENANT_ROLE_GUEST, apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED:
			// noop
		default:
			// noop
		}
	}

	// Check if requested roles do not exceed existing roles

	// first check if the requested role subject is part of the token subject
	for reqProjectID, reqRole := range requestedProjectRoles {
		if reqRole == apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED {
			return fmt.Errorf("requested project role:%q is not allowed", reqRole.String())
		}

		projectRole, ok := tokenProjectRoles[reqProjectID]
		if !ok {
			return fmt.Errorf("requested project:%q is not allowed", reqProjectID)
		}

		// OWNER has the lowest index
		if reqRole < projectRole {
			return fmt.Errorf("requested role:%q is higher than allowed role:%q", reqRole.String(), projectRole.String())
		}
	}

	for reqTenantID, reqRole := range requestedTenantRoles {
		if reqRole == apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED {
			return fmt.Errorf("requested tenant role:%q is not allowed", reqRole.String())
		}

		tenantRole, ok := tokenTenantRoles[reqTenantID]
		if !ok {
			return fmt.Errorf("requested tenant:%q is not allowed", reqTenantID)
		}

		// OWNER has the lowest index
		if reqRole < tenantRole {
			return fmt.Errorf("requested role:%q is higher than allowed role:%q", reqRole.String(), tenantRole.String())
		}
	}

	if requestedAdminRole != nil {
		if currentToken.AdminRole == nil {
			return fmt.Errorf("requested admin role:%q is not allowed", requestedAdminRole.String())
		}

		if *requestedAdminRole == apiv1.AdminRole_ADMIN_ROLE_UNSPECIFIED {
			return fmt.Errorf("requested admin role:%q is not allowed", requestedAdminRole.String())
		}

		if *requestedAdminRole < *currentToken.AdminRole {
			return fmt.Errorf("requested admin role:%q is not allowed", requestedAdminRole.String())
		}
	}

	// Validate Expire
	if req.Expires.AsDuration() > tokenutil.MaxExpiration {
		return fmt.Errorf("requested expiration duration:%q exceeds max expiration:%q", req.Expires.AsDuration(), tokenutil.MaxExpiration)
	}

	return nil
}
