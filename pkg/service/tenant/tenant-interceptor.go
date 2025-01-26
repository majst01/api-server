package tenant

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	"github.com/metal-stack/api-server/pkg/token"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/cache"
	"github.com/metal-stack/security"
)

type (
	tenantInterceptor struct {
		projectCache *cache.Cache[string, *mdcv1.Project]
		log          *slog.Logger
		masterClient mdc.Client
	}

	projectRequest interface {
		GetProject() string
	}

	tenantRequest interface {
		GetLogin() string
	}
)

func NewInterceptor(log *slog.Logger, masterClient mdc.Client) *tenantInterceptor {
	return &tenantInterceptor{
		projectCache: cache.New(1*time.Hour, func(ctx context.Context, id string) (*mdcv1.Project, error) {
			pgr, err := masterClient.Project().Get(ctx, &mdcv1.ProjectGetRequest{Id: id})
			if err != nil {
				return nil, fmt.Errorf("unable to get project: %w", err)
			}
			return pgr.GetProject(), nil
		}),
		log:          log,
		masterClient: masterClient,
	}
}

// TenantUnaryInterceptor will check if the request targets a project, if yes, checks if tenant of this project
// already exists, if not an error is returned.
func (i *tenantInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		var (
			tenant  *mdcv1.Tenant
			project *mdcv1.Project
			user    = &security.User{
				EMail:   "",
				Name:    "",
				Tenant:  "",
				Groups:  []security.ResourceAccess{},
				Issuer:  "",
				Subject: "",
			}
		)

		tok, tokenInCtx := token.TokenFromContext(ctx)
		if tokenInCtx {
			user.Subject = tok.UserId
		}

		switch rq := req.Any().(type) {
		case projectRequest:
			projectID := rq.GetProject()
			i.log.Debug("tenant interceptor", "request-scope", "project", "id", projectID)

			var err error
			project, err = i.projectCache.Get(ctx, projectID)
			if mdcv1.IsNotFound(err) {
				return nil, connect.NewError(connect.CodeNotFound, err)
			}
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			// TODO: use cache? ==> but then refresh when tenant gets updated because fields may change
			tgr, err := i.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{Id: project.TenantId})
			if mdcv1.IsNotFound(err) {
				return nil, connect.NewError(connect.CodeNotFound, err)
			}
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			tenant = tgr.Tenant

			user.Tenant = tgr.Tenant.Meta.Id
			user.EMail = tgr.Tenant.Meta.Annotations[tutil.TagEmail]
		case tenantRequest:
			tenantID := rq.GetLogin()
			i.log.Debug("tenant interceptor", "request-scope", "tenant", "id", tenantID)

			tgr, err := i.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{Id: tenantID})
			if mdcv1.IsNotFound(err) {
				return nil, connect.NewError(connect.CodeNotFound, err)
			}
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			tenant = tgr.Tenant

			user.Tenant = tgr.Tenant.Meta.Id
			user.EMail = tgr.Tenant.Meta.Annotations[tutil.TagEmail]
		default:
			// TODO: IMHO it would be better to do directly after looking up the token from the ctx and not only in the default case? (api-server#538)
			if !tokenInCtx || tok == nil {
				i.log.Debug("tenant interceptor", "request-scope", "public")

				// update the context with the user information BEFORE calling next
				ctx = security.PutUserInContext(ctx, user)

				// allow unauthenticated requests
				return next(ctx, req)
			}

			i.log.Debug("tenant interceptor", "request-scope", "other")

			tgr, err := i.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{Id: tok.UserId})
			if mdcv1.IsNotFound(err) {
				return nil, connect.NewError(connect.CodeNotFound, err)
			}
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			tenant = tgr.Tenant

			user.Tenant = tgr.Tenant.Meta.Id
			user.EMail = tgr.Tenant.Meta.Annotations[tutil.TagEmail]
		}

		ctx = tutil.ContextWithProjectAndTenant(ctx, project, tenant)

		// update the context with the user information BEFORE calling next
		ctx = security.PutUserInContext(ctx, user)

		return next(ctx, req)
	})
}

func (i *tenantInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return connect.StreamingClientFunc(func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	})
}
func (i *tenantInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return next(ctx, conn)
	})
}
