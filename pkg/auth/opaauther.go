package auth

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	authentication "github.com/metal-stack/api-server/pkg/auth/authentication"
	authorization "github.com/metal-stack/api-server/pkg/auth/authorization"
	"github.com/metal-stack/api-server/pkg/certs"
	putil "github.com/metal-stack/api-server/pkg/project"
	"github.com/metal-stack/api-server/pkg/service/method"
	"github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/permissions"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/cache"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

// TODO check https://github.com/akshayjshah/connectauth for optimization

const (
	authorizationHeader = "authorization"
)

type (
	Config struct {
		Log            *slog.Logger
		CertStore      certs.CertStore
		CertCacheTime  *time.Duration
		TokenStore     token.TokenStore
		AllowedIssuers []string
		AdminSubjects  []string
		MasterClient   mdc.Client
	}

	// opa is a gRPC server authorizer using OPA as backend
	opa struct {
		authenticationQuery      *rego.PreparedEvalQuery
		authorizationQuery       *rego.PreparedEvalQuery
		log                      *slog.Logger
		visibility               permissions.Visibility
		servicePermissions       *permissions.ServicePermissions
		certCache                *cache.Cache[any, *cacheReturn]
		tokenStore               token.TokenStore
		adminSubjects            []string
		projectsAndTenantsGetter func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error)
	}

	cacheReturn struct {
		raw string
		set jwk.Set
	}

	authorizationDecision struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}

	authenticationDecision struct {
		Valid   bool   `json:"valid"`
		Subject string `json:"subject"`
		JwtID   string `json:"id"`
		Reason  string `json:"reason"`
	}

	printHook struct {
		log *slog.Logger
	}
)

func (p *printHook) Print(ctx print.Context, msg string) error {
	p.log.Debug("rego evaluation", "print output", msg, "print context", ctx)
	return nil
}

// New creates an OPA authorizer
func New(c Config) (*opa, error) {
	var (
		log                = c.Log.WithGroup("opa")
		ctx                = context.Background()
		servicePermissions = permissions.GetServicePermissions()
	)

	authenticationQ, err := newAuthenticationQuery(ctx, log, c.AllowedIssuers)
	if err != nil {
		return nil, err
	}

	authorizationQ, err := newAuthorizationQuery(ctx, log, servicePermissions)
	if err != nil {
		return nil, err
	}

	certCacheTime := 60 * time.Minute
	if c.CertCacheTime != nil {
		certCacheTime = *c.CertCacheTime
	}

	return &opa{
		log: log,
		certCache: cache.New(certCacheTime, func(ctx context.Context, id any) (*cacheReturn, error) {
			set, raw, err := c.CertStore.PublicKeys(ctx)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve signing certs: %w", err)
			}
			return &cacheReturn{
				set: set,
				raw: raw,
			}, nil
		}),
		tokenStore:          c.TokenStore,
		authenticationQuery: &authenticationQ,
		authorizationQuery:  &authorizationQ,
		visibility:          servicePermissions.Visibility,
		servicePermissions:  servicePermissions,
		adminSubjects:       c.AdminSubjects,
		projectsAndTenantsGetter: func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error) {
			return putil.GetProjectsAndTenants(ctx, c.MasterClient, userId)
		},
	}, nil
}

func newOpaQuery(ctx context.Context, log *slog.Logger, fs embed.FS, query string, data map[string]any) (rego.PreparedEvalQuery, error) {
	files, err := fs.ReadDir(".")
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}

	var moduleLoads []func(r *rego.Rego)
	for _, f := range files {
		content, err := fs.ReadFile(f.Name())
		if err != nil {
			return rego.PreparedEvalQuery{}, err
		}
		moduleLoads = append(moduleLoads, rego.Module(f.Name(), string(content)))
	}

	moduleLoads = append(moduleLoads, rego.Query(query))
	moduleLoads = append(moduleLoads, rego.EnablePrintStatements(true))
	moduleLoads = append(moduleLoads, rego.PrintHook(&printHook{
		log: log,
	}))
	moduleLoads = append(moduleLoads, rego.Store(inmem.NewFromObject(data)))

	return rego.New(
		moduleLoads...,
	).PrepareForEval(ctx)
}

func newAuthenticationQuery(ctx context.Context, log *slog.Logger, allowedIssuers []string) (rego.PreparedEvalQuery, error) {
	return newOpaQuery(ctx, log, authentication.Policies, "x = data.api.v1.metalstack.io.authentication.decision", map[string]any{
		"allowed_issuers": allowedIssuers,
	})
}

func newAuthorizationQuery(ctx context.Context, log *slog.Logger, servicePermissions *permissions.ServicePermissions) (rego.PreparedEvalQuery, error) {
	return newOpaQuery(ctx, log, authorization.Policies, "x = data.api.v1.metalstack.io.authorization.decision", map[string]any{
		"roles":      servicePermissions.Roles,
		"methods":    servicePermissions.Methods,
		"visibility": servicePermissions.Visibility,
	})
}

func (o *opa) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return connect.StreamingClientFunc(func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		o.log.Warn("streamclient called", "procedure", spec.Procedure)
		return next(ctx, spec)
	})
}

// WrapStreamingHandler is a Opa StreamServerInterceptor for the
// server. Only one stream interceptor can be installed.
// If you want to add extra functionality you might decorate this function.
func (o *opa) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if o.authenticationQuery == nil {
			return fmt.Errorf("opa engine not initialized properly, forgot AuthzLoad ?")
		}

		wrapper := &recvWrapper{
			StreamingHandlerConn: conn,
			ctx:                  ctx,
			o:                    o,
		}
		return next(ctx, wrapper)
	})
}

type recvWrapper struct {
	connect.StreamingHandlerConn
	ctx context.Context
	o   *opa
}

func (s *recvWrapper) Receive(m any) error {
	if err := s.StreamingHandlerConn.Receive(m); err != nil {
		return err
	}
	_, err := s.o.decide(s.ctx, s.StreamingHandlerConn.Spec().Procedure, s.StreamingHandlerConn.RequestHeader().Get, m)
	if err != nil {
		return err
	}

	return nil
}

// WrapUnary is a Opa UnaryServerInterceptor for the
// server. Only one unary interceptor can be installed.
// If you want to add extra functionality you might decorate this function.
func (o *opa) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	// Same as previous UnaryInterceptorFunc.
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		o.log.Debug("authz unary", "req", req)
		if o.authenticationQuery == nil {
			return nil, fmt.Errorf("opa engine not initialized properly, forgot AuthzLoad ?")
		}

		t, err := o.decide(ctx, req.Spec().Procedure, req.Header().Get, req.Any())
		if err != nil {
			return nil, err
		}

		// Store the token in the context for later use in the service methods
		if t != nil {
			ctx = token.ContextWithToken(ctx, t)
		}

		resp, err := next(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("unable to process request %w", err)
		}

		return resp, err
	})
}

func (o *opa) decide(ctx context.Context, methodName string, jwtTokenfunc func(string) string, req any) (*v1.Token, error) {
	// Allow all methods which have public visibility defined in the proto definition
	// o.log.Debug("authorize", "method", methodName, "req", req, "visibility", o.visibility, "servicepermissions", *o.servicePermissions)

	jwks, err := o.certCache.Get(ctx, nil)
	if err != nil {
		return nil, err
	}

	if jwks.set.Len() == 0 {
		// in the initial startup phase it can happen that authorize gets called even if there are no public signing keys yet
		// in this case due to caching there is no possibility to authenticate for 60 minutes until the cache has expired
		// so we refresh the cache if nothing was found.
		jwks, err = o.certCache.Refresh(ctx, nil)
		if err != nil {
			return nil, err
		}
	}

	var (
		bearer         = jwtTokenfunc(authorizationHeader)
		_, jwtToken, _ = strings.Cut(bearer, " ")
		t              *v1.Token
		projectRoles   map[string]v1.ProjectRole
		tenantRoles    map[string]v1.TenantRole
		permissions    map[string]*v1.MethodPermission
		adminRole      *v1.AdminRole
	)
	jwtToken = strings.TrimSpace(jwtToken)

	if jwtToken != "" {
		decision, err := o.authenticate(ctx, map[string]any{
			"token": jwtToken,
			"jwks":  jwks.raw,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		if !decision.Valid {
			if decision.Reason != "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New(decision.Reason))
			}

			return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token is invalid or has expired"))
		}

		t, err = o.tokenStore.Get(ctx, decision.Subject, decision.JwtID)
		if err != nil {
			if errors.Is(err, token.ErrTokenNotFound) {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token was revoked"))
			}

			return nil, connect.NewError(connect.CodeInternal, err)
		}

		if t.TokenType == v1.TokenType_TOKEN_TYPE_API {
			projectRoles := t.ProjectRoles
			tenantRoles := t.TenantRoles
			permissions := method.PermissionsBySubject(t)
			adminRole := t.AdminRole

			decision, err := o.authorize(ctx, newOpaAuthorizationRequest(methodName, req, t, permissions, projectRoles, tenantRoles, adminRole))
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			if !decision.Allow {
				if decision.Reason != "" {
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.New(decision.Reason))
				}

				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: %s", methodName))
			}
		}

		// we fetch user permissions from the masterdata-api which is costly but our single source of truth
		// this way we do not need to struggle updating all the permissions of tokens that were issued in the past
		// if performance becomes an issue we need to reconsider this solution

		pat, err := o.projectsAndTenantsGetter(ctx, t.UserId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		projectRoles = pat.ProjectRoles
		tenantRoles = pat.TenantRoles
		permissions = nil // consoletokens should never have permissions cause they are not stored in the masterdata-db
		if slices.Contains(o.adminSubjects, t.UserId) {
			// we do not store admin roles in the masterdata-api, but we can use this from the static configuration passed to the api-server
			adminRole = t.AdminRole
		}

		if t.TokenType == v1.TokenType_TOKEN_TYPE_CONSOLE {
			// as we do not store roles in the console token, we set the roles from the information in the masterdata-db
			t.ProjectRoles = projectRoles
			t.TenantRoles = tenantRoles
			t.AdminRole = adminRole
		}
	}

	decision, err := o.authorize(ctx, newOpaAuthorizationRequest(methodName, req, t, permissions, projectRoles, tenantRoles, adminRole))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	if decision.Allow {
		return t, nil
	}

	if decision.Reason != "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New(decision.Reason))
	}

	return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: %s", methodName))
}

func (o *opa) authenticate(ctx context.Context, input map[string]any) (authenticationDecision, error) {
	return evalResult[authenticationDecision](ctx, o.log.WithGroup("authentication"), o.authenticationQuery, input)
}

func (o *opa) authorize(ctx context.Context, input map[string]any) (authorizationDecision, error) {
	return evalResult[authorizationDecision](ctx, o.log.WithGroup("authorization"), o.authorizationQuery, input)
}

func newOpaAuthorizationRequest(method string, req any, token *v1.Token, methodPermissions map[string]*v1.MethodPermission, projectRoles map[string]v1.ProjectRole, tenantRoles map[string]v1.TenantRole, adminRole *v1.AdminRole) map[string]any {
	input := map[string]any{
		"method":  method,
		"request": req,
		"token":   token,
	}

	if len(methodPermissions) > 0 {
		permissions := map[string][]string{}
		for subject, methodPerms := range methodPermissions {
			permissions[subject] = append(permissions[subject], methodPerms.Methods...)
		}

		input["permissions"] = permissions
	}

	if len(projectRoles) > 0 {
		roles := map[string]string{}
		for project, role := range projectRoles {
			roles[project] = role.String()
		}
		input["project_roles"] = roles
	}

	if len(tenantRoles) > 0 {
		roles := map[string]string{}
		for tenant, role := range tenantRoles {
			roles[tenant] = role.String()
		}
		input["tenant_roles"] = roles
	}

	if adminRole != nil {
		input["admin_role"] = adminRole.String()
	}

	return input
}

func evalResult[R any](ctx context.Context, log *slog.Logger, query *rego.PreparedEvalQuery, input map[string]any) (R, error) {
	log.Debug("rego query evaluation", "input", input)

	var zero R

	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return zero, fmt.Errorf("error evaluating rego result set: %w", err)
	}

	if len(results) == 0 {
		return zero, fmt.Errorf("error evaluating rego result set: result have no length")
	}

	decision, ok := results[0].Bindings["x"].(map[string]any)
	if !ok {
		return zero, fmt.Errorf("error evaluating rego result set: no map contained in decision")
	}

	raw, err := json.Marshal(decision)
	if err != nil {
		return zero, fmt.Errorf("unable to marshal json: %w", err)
	}

	var res R
	err = json.Unmarshal(raw, &res)
	if err != nil {
		return zero, fmt.Errorf("unable to unmarshal json: %w", err)
	}

	// only for devel:
	// log.Debug("made auth decision", "results", results)

	return res, nil
}
