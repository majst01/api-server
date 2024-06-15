package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/metal-stack/api-server/pkg/auth/policies"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/service/method"
	"github.com/metal-stack/api-server/pkg/token"
	"github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/permissions"
	"github.com/metal-stack/metal-lib/pkg/cache"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/redis/go-redis/v9"
)

// TODO check https://github.com/akshayjshah/connectauth for optimization

const (
	authorizationHeader = "authorization"
)

type Config struct {
	Log            *slog.Logger
	CertStore      certs.CertStore
	CertCacheTime  *time.Duration
	TokenStore     token.TokenStore
	AllowedIssuers []string
}

type printHook struct {
	log *slog.Logger
}

func (p *printHook) Print(_ print.Context, msg string) error {
	p.log.Debug("rego evaluation", "print output", msg)
	return nil
}

// opa is a gRPC server authorizer using OPA as backend
type opa struct {
	qDecision          *rego.PreparedEvalQuery
	log                *slog.Logger
	visibility         permissions.Visibility
	servicePermissions *permissions.ServicePermissions
	certCache          *cache.Cache[any, *cacheReturn]
	tokenStore         token.TokenStore
}

type cacheReturn struct {
	raw string
	set jwk.Set
}

// New creates an OPA authorizer
func New(c Config) (*opa, error) {
	files, err := policies.RegoPolicies.ReadDir(".")
	if err != nil {
		return nil, err
	}

	var moduleLoads []func(r *rego.Rego)
	for _, f := range files {
		content, err := policies.RegoPolicies.ReadFile(f.Name())
		if err != nil {
			return nil, err
		}
		moduleLoads = append(moduleLoads, rego.Module(f.Name(), string(content)))
	}

	servicePermissions := permissions.GetServicePermissions()
	// will be accessible as data.secret/roles/methods in rego rules
	data := inmem.NewFromObject(map[string]any{
		"roles":           servicePermissions.Roles,
		"methods":         servicePermissions.Methods,
		"visibility":      servicePermissions.Visibility,
		"allowed_issuers": c.AllowedIssuers,
	})

	log := c.Log.WithGroup("opa")

	moduleLoads = append(moduleLoads, rego.Query("x = data.api.v1.metalstack.io.authz.decision"))
	moduleLoads = append(moduleLoads, rego.EnablePrintStatements(true))
	moduleLoads = append(moduleLoads, rego.PrintHook(&printHook{
		log: log,
	}))
	moduleLoads = append(moduleLoads, rego.Store(data))

	qDecision, err := rego.New(
		moduleLoads...,
	).PrepareForEval(context.Background())
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
		tokenStore:         c.TokenStore,
		qDecision:          &qDecision,
		visibility:         servicePermissions.Visibility,
		servicePermissions: servicePermissions,
	}, nil

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
		if o.qDecision == nil {
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
	_, err := s.o.authorize(s.ctx, s.StreamingHandlerConn.Spec().Procedure, s.StreamingHandlerConn.RequestHeader().Get, m)
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
		o.log.Info("authz unary", "req", req)
		if o.qDecision == nil {
			return nil, fmt.Errorf("opa engine not initialized properly, forgot AuthzLoad ?")
		}

		t, err := o.authorize(ctx, req.Spec().Procedure, req.Header().Get, req.Any())
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

func (o *opa) authorize(ctx context.Context, methodName string, jwtTokenfunc func(string) string, req any) (*apiv1.Token, error) {
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

	bearer := jwtTokenfunc(authorizationHeader)

	_, jwtToken, _ := strings.Cut(bearer, " ") // TODO: validation / extraction of bearer should be improved

	var (
		t            *apiv1.Token
		projectRoles map[string]apiv1.ProjectRole
		tenantRoles  map[string]apiv1.TenantRole
		permissions  map[string]*apiv1.MethodPermission
		adminRole    *apiv1.AdminRole
	)

	if jwtToken != "" {
		// we validate the jwt in opa, so it's okay to already extract permissions from unverified token here
		// TODO: validate token with OPA here (not check authorization yet) and get claims, then we have a valid token for sure
		// https://www.openpolicyagent.org/docs/latest/extensions/#custom-built-in-functions-in-go
		claims, err := token.ParseJWTToken(jwtToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token"))
		}

		t, err = o.tokenStore.Get(ctx, claims.Subject, claims.ID)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token was revoked or has expired"))
			}
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		projectRoles = t.ProjectRoles
		tenantRoles = t.TenantRoles
		permissions = method.PermissionsBySubject(t)
		adminRole = t.AdminRole
	}

	ok, err := o.decide(ctx, newOpaRequest(methodName, req, permissions, projectRoles, tenantRoles, adminRole, jwtToken, jwks.raw), methodName)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	if ok {
		return t, nil
	}

	return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: %s", methodName))
}

func (o *opa) decide(ctx context.Context, input map[string]any, method string) (bool, error) {
	o.log.Debug("rego evaluation", "input", input)

	results, err := o.qDecision.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("error evaluating rego result set %w", err)
	}

	if len(results) == 0 {
		return false, fmt.Errorf("error evaluating rego result set: results have no length")
	}

	decision, ok := results[0].Bindings["x"].(map[string]any)
	if !ok {
		return false, fmt.Errorf("error evaluating rego result set: unexpected response type")
	}
	allow, ok := decision["allow"].(bool)
	if !ok {
		return false, fmt.Errorf("error evaluating rego result set: unexpected response type")
	}

	if !allow {
		reason, ok := decision["reason"].(string)
		if ok {
			return false, fmt.Errorf("access denied:%s", reason)
		}
		return false, fmt.Errorf("access denied to:%s", method)
	}

	// TODO remove, only for devel:
	o.log.Debug("made auth decision", "results", results)

	return allow, nil
}

func newOpaRequest(method string, req any, methodPermissions map[string]*apiv1.MethodPermission, projectRoles map[string]apiv1.ProjectRole, tenantRoles map[string]apiv1.TenantRole, adminRole *apiv1.AdminRole, token, jwks string) map[string]any {
	input := map[string]any{
		"method":  method,
		"request": req,
		"token":   token,
		"jwks":    jwks,
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
