package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/certs"
	putil "github.com/metal-stack/api-server/pkg/project"
	"github.com/metal-stack/api-server/pkg/service/method"
	tokenutil "github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/api/go/metalstack/api/v1/apiv1connect"
	"github.com/metal-stack/api/go/permissions"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
)

type Config struct {
	Log          *slog.Logger
	TokenStore   tokenutil.TokenStore
	CertStore    certs.CertStore
	MasterClient mdc.Client

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

	projectsAndTenantsGetter func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error)
}

type TokenService interface {
	apiv1connect.TokenServiceHandler
	CreateConsoleTokenWithoutPermissionCheck(ctx context.Context, subject string, expiration *time.Duration) (*connect.Response[v1.TokenServiceCreateResponse], error)
	CreateApiTokenWithoutPermissionCheck(ctx context.Context, rq *connect.Request[v1.TokenServiceCreateRequest]) (*connect.Response[v1.TokenServiceCreateResponse], error)
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

		projectsAndTenantsGetter: func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error) {
			return putil.GetProjectsAndTenants(ctx, c.MasterClient, userId)
		},
	}
}

// CreateConsoleTokenWithoutPermissionCheck is only called from the auth service during login through console
// No validation against requested roles and permissions is required and implemented here
func (t *tokenService) CreateConsoleTokenWithoutPermissionCheck(ctx context.Context, subject string, expiration *time.Duration) (*connect.Response[v1.TokenServiceCreateResponse], error) {
	expires := tokenutil.DefaultExpiration
	if expiration != nil {
		expires = *expiration
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to fetch signing certificate: %w", err))
	}

	secret, token, err := tokenutil.NewJWT(v1.TokenType_TOKEN_TYPE_CONSOLE, subject, t.issuer, expires, privateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to create console token: %w", err))
	}

	err = t.tokens.Set(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceCreateResponse{
		Token:  token,
		Secret: secret,
	}), nil
}

// CreateApiTokenWithoutPermissionCheck is only called from the api-server command line interface
// No validation against requested roles and permissions is required and implemented here
func (t *tokenService) CreateApiTokenWithoutPermissionCheck(ctx context.Context, rq *connect.Request[v1.TokenServiceCreateRequest]) (*connect.Response[v1.TokenServiceCreateResponse], error) {
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

	secret, token, err := tokenutil.NewJWT(v1.TokenType_TOKEN_TYPE_API, "api-server-cli", t.issuer, expires, privateKey)
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

	return connect.NewResponse(&v1.TokenServiceCreateResponse{
		Token:  token,
		Secret: secret,
	}), nil
}

// Get returns the token by a given uuid for the user who requests it.
func (t *tokenService) Get(ctx context.Context, rq *connect.Request[v1.TokenServiceGetRequest]) (*connect.Response[v1.TokenServiceGetResponse], error) {
	t.log.Debug("get", "token", rq)

	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	res, err := t.tokens.Get(ctx, token.UserId, rq.Msg.Uuid)
	if err != nil {
		if errors.Is(err, tokenutil.ErrTokenNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceGetResponse{
		Token: res,
	}), nil
}

// Update updates a given token of a user.
// We need to prevent a user from elevating permissions here.
func (t *tokenService) Update(ctx context.Context, rq *connect.Request[v1.TokenServiceUpdateRequest]) (*connect.Response[v1.TokenServiceUpdateResponse], error) {
	t.log.Debug("update", "token", rq)
	req := rq.Msg

	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	// we first validate token permission elevation for the token used in the token update request,
	// which might be an API token with restricted permissions

	createRequest := &v1.TokenServiceCreateRequest{
		Permissions:  req.Permissions,
		ProjectRoles: req.ProjectRoles,
		TenantRoles:  req.TenantRoles,
		AdminRole:    req.AdminRole,
	}

	err := validateTokenCreate(token, createRequest, t.servicePermissions, t.adminSubjects)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}

	// now, we validate if the user is still permitted to update the token
	// doing this check is not strictly necessary because the resulting token would fail in the opa auther when being compared
	// to the actual user permissions, but it's nicer for the user to already prevent token update immediately in this place

	projectsAndTenants, err := t.projectsAndTenantsGetter(ctx, token.GetUserId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	fullUserToken := &v1.Token{
		UserId:       token.UserId,
		ProjectRoles: projectsAndTenants.ProjectRoles,
		TenantRoles:  projectsAndTenants.TenantRoles,
		AdminRole:    nil,
	}
	if slices.Contains(t.adminSubjects, token.UserId) {
		fullUserToken.AdminRole = v1.AdminRole_ADMIN_ROLE_EDITOR.Enum()
	}
	err = validateTokenCreate(fullUserToken, createRequest, t.servicePermissions, t.adminSubjects)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("outdated token: %w", err))
	}

	// now follows the update

	tokenToUpdate, err := t.tokens.Get(ctx, token.UserId, rq.Msg.Uuid)
	if err != nil {
		if errors.Is(err, tokenutil.ErrTokenNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if tokenToUpdate.TokenType != v1.TokenType_TOKEN_TYPE_API {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("only updating API tokens is currently supported"))
	}

	if req.Description != nil {
		tokenToUpdate.Description = *req.Description
	}
	if req.AdminRole != nil {
		if *req.AdminRole == v1.AdminRole_ADMIN_ROLE_UNSPECIFIED {
			tokenToUpdate.AdminRole = nil
		} else {
			tokenToUpdate.AdminRole = req.AdminRole
		}
	}

	tokenToUpdate.Permissions = req.Permissions
	tokenToUpdate.ProjectRoles = req.ProjectRoles
	tokenToUpdate.TenantRoles = req.TenantRoles

	err = t.tokens.Set(ctx, tokenToUpdate)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceUpdateResponse{
		Token: tokenToUpdate,
	}), nil
}

// Create is called by users to issue new API tokens. This can be done from console tokens but also from other API tokens which have the permission to call token create.
// We need to prevent a user from elevating permissions here.
func (t *tokenService) Create(ctx context.Context, rq *connect.Request[v1.TokenServiceCreateRequest]) (*connect.Response[v1.TokenServiceCreateResponse], error) {
	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}
	req := rq.Msg

	// we first validate token permission elevation for the token used in the token create request,
	// which might be an API token with restricted permissions

	err := validateTokenCreate(token, req, t.servicePermissions, t.adminSubjects)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}

	// now, we validate if the user is still permitted to create such a token
	// doing this check is not strictly necessary because the resulting token would fail in the opa auther when being compared
	// to the actual user permissions, but it's nicer for the user to already prevent token creation immediately in this place

	projectsAndTenants, err := t.projectsAndTenantsGetter(ctx, token.GetUserId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	fullUserToken := &v1.Token{
		UserId:       token.UserId,
		ProjectRoles: projectsAndTenants.ProjectRoles,
		TenantRoles:  projectsAndTenants.TenantRoles,
		AdminRole:    nil,
	}
	if slices.Contains(t.adminSubjects, token.UserId) {
		fullUserToken.AdminRole = v1.AdminRole_ADMIN_ROLE_EDITOR.Enum()
	}
	err = validateTokenCreate(fullUserToken, req, t.servicePermissions, t.adminSubjects)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("outdated token: %w", err))
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	secret, token, err := tokenutil.NewJWT(v1.TokenType_TOKEN_TYPE_API, token.GetUserId(), t.issuer, req.Expires.AsDuration(), privateKey)
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

	resp := &v1.TokenServiceCreateResponse{
		Token:  token,
		Secret: secret,
	}

	return connect.NewResponse(resp), nil
}

// List lists the tokens of a specific user.
func (t *tokenService) List(ctx context.Context, _ *connect.Request[v1.TokenServiceListRequest]) (*connect.Response[v1.TokenServiceListResponse], error) {
	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	tokens, err := t.tokens.List(ctx, token.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceListResponse{
		Tokens: tokens,
	}), nil
}

// Revoke revokes a token of a given user and token ID.
func (t *tokenService) Revoke(ctx context.Context, rq *connect.Request[v1.TokenServiceRevokeRequest]) (*connect.Response[v1.TokenServiceRevokeResponse], error) {
	token, ok := tokenutil.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	err := t.tokens.Revoke(ctx, token.UserId, rq.Msg.Uuid)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceRevokeResponse{}), nil
}

func validateTokenCreate(currentToken *v1.Token, req *v1.TokenServiceCreateRequest, servicePermissions *permissions.ServicePermissions, adminIDs []string) error {
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
		case v1.TenantRole_TENANT_ROLE_EDITOR, v1.TenantRole_TENANT_ROLE_OWNER:
			currentToken.AdminRole = pointer.Pointer(v1.AdminRole_ADMIN_ROLE_EDITOR)
		case v1.TenantRole_TENANT_ROLE_VIEWER:
			currentToken.AdminRole = pointer.Pointer(v1.AdminRole_ADMIN_ROLE_VIEWER)
		case v1.TenantRole_TENANT_ROLE_GUEST, v1.TenantRole_TENANT_ROLE_UNSPECIFIED:
			// noop
		default:
			// noop
		}
	}

	// Check if requested roles do not exceed existing roles

	// first check if the requested role subject is part of the token subject
	for reqProjectID, reqRole := range requestedProjectRoles {
		if reqRole == v1.ProjectRole_PROJECT_ROLE_UNSPECIFIED {
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
		if reqRole == v1.TenantRole_TENANT_ROLE_UNSPECIFIED {
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

		if *requestedAdminRole == v1.AdminRole_ADMIN_ROLE_UNSPECIFIED {
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
