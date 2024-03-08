package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/metal-stack/api-server/pkg/auth/policies"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/token"
	"github.com/metal-stack/api/go/permissions"
	"github.com/metal-stack/metal-lib/pkg/cache"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown/print"
)

// TODO check https://github.com/akshayjshah/connectauth for optimization

const (
	authorizationHeader = "authorization"
)

type Config struct {
	Log            *slog.Logger
	CertStore      certs.CertStore
	CertCacheTime  *time.Duration
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

		claims, err := o.authorize(ctx, req.Spec().Procedure, req.Header().Get, req.Any())
		if err != nil {
			return nil, err
		}

		// Store the Claims in the context for later evaluation
		if claims != nil {
			ctx = token.ContextWithTokenClaims(ctx, claims)
		}

		resp, err := next(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("unable to process request %w", err)
		}
		return resp, err
	})
}

func (o *opa) authorize(ctx context.Context, methodName string, jwtTokenfunc func(string) string, req any) (*token.Claims, error) {
	// Allow all methods which have public visibility defined in the proto definition
	// o.log.Debug("authorize", "method", methodName, "req", req, "visibility", o.visibility, "servicepermissions", *o.servicePermissions)

	bearer := jwtTokenfunc(authorizationHeader)

	_, jwtToken, _ := strings.Cut(bearer, " ")

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

	ok, err := o.decide(ctx, newOpaRequest(methodName, req, jwtToken, jwks.raw), methodName)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	if ok {
		return token.ParseJWTToken(jwtToken)
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

func newOpaRequest(method string, req any, token, jwks string) map[string]any {
	return map[string]any{
		"method":  method,
		"request": req,
		"token":   token,
		"jwks":    jwks,
	}
}
