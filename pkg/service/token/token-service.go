package token

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"github.com/metal-stack/api/go/permissions"
)

type Config struct {
	Log        *slog.Logger
	TokenStore token.TokenStore
	CertStore  certs.CertStore

	// AdminSubjects are the subjects for which the token service allows the creation of admin api tokens
	// this is typically a Github Org of the provider
	AdminSubjects []string

	// Issuer to sign the JWT Token with
	Issuer string
}

type tokenService struct {
	issuer             string
	adminSubjects      []string
	tokens             token.TokenStore
	certs              certs.CertStore
	log                *slog.Logger
	servicePermissions *permissions.ServicePermissions
}

type TokenService interface {
	apiv1connect.TokenServiceHandler
	CreateConsoleTokenWithoutPermissionCheck(ctx context.Context, subject string, rq *connect.Request[v1.TokenServiceCreateRequest]) (*connect.Response[v1.TokenServiceCreateResponse], error)
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
	}
}

// CreateConsoleTokenWithoutPermissionCheck is only called from the auth service during login through console
// No validation against requested roles and permissions is required and implemented here
func (t *tokenService) CreateConsoleTokenWithoutPermissionCheck(ctx context.Context, subject string, rq *connect.Request[v1.TokenServiceCreateRequest]) (*connect.Response[v1.TokenServiceCreateResponse], error) {
	t.log.Debug("create", "token", rq)
	req := rq.Msg

	expires := token.DefaultExpiration
	if req.Expires != nil {
		expires = req.Expires.AsDuration()
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to fetch signing certificate: %w", err))
	}

	secret, token, err := token.NewJWT(v1.TokenType_TOKEN_TYPE_CONSOLE, subject, t.issuer, req.Roles, req.Permissions, expires, privateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to create console token: %w", err))
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

	expires := token.DefaultExpiration
	if req.Expires != nil {
		expires = req.Expires.AsDuration()
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	secret, token, err := token.NewJWT(v1.TokenType_TOKEN_TYPE_API, "api-server-cli", t.issuer, req.Roles, req.Permissions, expires, privateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	token.Description = req.Description

	err = t.tokens.Set(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceCreateResponse{
		Token:  token,
		Secret: secret,
	}), nil
}

// Create implements TokenService.
// TODO User is actually not able to select the Roles because there is no API Endpoint to fetch them
func (t *tokenService) Create(ctx context.Context, rq *connect.Request[v1.TokenServiceCreateRequest]) (*connect.Response[v1.TokenServiceCreateResponse], error) {
	claims, ok := token.TokenClaimsFromContext(ctx)
	if !ok || claims == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no claims found in request"))
	}
	req := rq.Msg

	err := validateTokenCreate(claims, req, t.servicePermissions, t.adminSubjects)
	if err != nil {
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	}

	privateKey, err := t.certs.LatestPrivate(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	secret, token, err := token.NewJWT(v1.TokenType_TOKEN_TYPE_API, claims.Subject, t.issuer, req.Roles, req.Permissions, req.Expires.AsDuration(), privateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	token.Description = req.Description

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

// List implements TokenService.
func (t *tokenService) List(ctx context.Context, _ *connect.Request[v1.TokenServiceListRequest]) (*connect.Response[v1.TokenServiceListResponse], error) {
	claims, ok := token.TokenClaimsFromContext(ctx)
	if !ok || claims == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no claims found in request"))
	}

	tokens, err := t.tokens.List(ctx, claims.Subject)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceListResponse{
		Tokens: tokens,
	}), nil
}

// Revoke implements TokenService.
func (t *tokenService) Revoke(ctx context.Context, rq *connect.Request[v1.TokenServiceRevokeRequest]) (*connect.Response[v1.TokenServiceRevokeResponse], error) {
	claims, ok := token.TokenClaimsFromContext(ctx)
	if !ok || claims == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no claims found in request"))
	}
	token := &v1.Token{
		UserId: claims.Subject,
		Uuid:   rq.Msg.Uuid,
	}

	err := t.tokens.Revoke(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.TokenServiceRevokeResponse{}), nil
}

func validateTokenCreate(claims *token.Claims, req *v1.TokenServiceCreateRequest, servicePermissions *permissions.ServicePermissions, adminSubjects []string) error {
	// First check all requested permissions are defined in servicePermissions

	// if claim permissions are empty fill them from claim roles
	// methods restrictions are inherited from the user role for every project
	if len(claims.Permissions) == 0 {
		claims.Permissions = token.AllowedMethods(servicePermissions, claims)
	}

	requestedPermissions := req.Permissions
	claimPermissions := claims.Permissions
	for _, reqSubjectPermission := range requestedPermissions {
		reqSubjectID := reqSubjectPermission.Subject
		// Check if the requested subject, e.g. project or organization can be accessed
		claimProjectPermissions, ok := claimPermissions[reqSubjectID]
		if !ok {
			return fmt.Errorf("requested subject:%q access is not allowed", reqSubjectID)
		}

		for _, reqMethod := range reqSubjectPermission.Methods {
			// Check if the requested permissions are part of all available methods
			if !servicePermissions.Methods[reqMethod] {
				return fmt.Errorf("requested method:%q is not allowed", reqMethod)
			}

			// Check if the requested permissions are part of the claim
			if !slices.Contains(claimProjectPermissions, reqMethod) {
				return fmt.Errorf("requested method:%q is not allowed for subject:%q", reqMethod, reqSubjectID)
			}
		}
	}

	// Check if requested roles do not exceed existing roles
	requestedRoles := req.Roles
	claimRoles := claims.Roles

	for _, subject := range adminSubjects {
		role, ok := claimRoles[subject]
		if ok && (role == v1.EDITOR || role == v1.ADMIN || role == v1.OWNER) {
			// TODO maybe we put the actual role in here and make it possible to have finer grained rego rules against
			// e.g. claimRoles["*"] = "editor"
			claimRoles["*"] = "admin"
			break
		}
	}

	// first check if the requested role subject is part of the claim subject
	for _, reqRole := range requestedRoles {
		claimRole, ok := claimRoles[reqRole.Subject]
		if !ok {
			return fmt.Errorf("requested subject:%q is not allowed", reqRole.Subject)
		}
		claimRoleIndex := slices.Index(v1.RolesDescending, claimRole)
		if claimRoleIndex < 0 {
			return fmt.Errorf("claim role:%q is not known", claimRole)
		}

		reqRoleIndex := slices.Index(v1.RolesDescending, reqRole.Role)
		if reqRoleIndex < 0 {
			return fmt.Errorf("requested role:%q is not known", reqRole.Role)
		}
		// ADMIN has the lowest index
		if reqRoleIndex < claimRoleIndex {
			return fmt.Errorf("requested role:%q is higher than allowed role:%q", reqRole.Role, claimRole)
		}
	}

	// Validate Expire
	if req.Expires.AsDuration() > token.MaxExpiration {
		return fmt.Errorf("requested expiration duration:%q exceeds max expiration:%q", req.Expires.AsDuration(), token.MaxExpiration)
	}
	return nil
}
