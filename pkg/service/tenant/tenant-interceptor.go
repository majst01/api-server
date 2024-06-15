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

type tenantInterceptor struct {
	projectCache *cache.Cache[string, *mdcv1.Project]
	log          *slog.Logger
	masterClient mdc.Client
}

type projectRequest interface {
	GetProject() string
}

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
			email   = ""
			name    = ""
			tenant  = ""
			subject = ""
		)

		t, ok := token.TokenFromContext(ctx)
		if ok {
			subject = t.UserId
		}

		defer func() {
			// after we know project and tenant, we can set the user for auditing
			ctx = security.PutUserInContext(ctx, &security.User{
				EMail:   email,
				Name:    name,
				Tenant:  tenant,
				Groups:  []security.ResourceAccess{},
				Issuer:  "",
				Subject: subject,
			})
		}()

		rq := req.Any()
		switch pr := rq.(type) {
		case projectRequest:
			projectID := pr.GetProject()
			i.log.Debug("tenant interceptor", "project", projectID)

			project, err := i.projectCache.Get(ctx, projectID)
			if err != nil {
				return nil, connect.NewError(connect.CodeNotFound, err)
			}

			// TODO: use cache? ==> but then refresh when tenant gets updated because fields may change
			tgr, err := i.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{Id: project.TenantId})
			if err != nil {
				i.log.Error("unary", "tenant does not exist", project.TenantId, "error", err)
				return nil, connect.NewError(connect.CodeNotFound, err)
			}

			tenant = tgr.Tenant.Meta.Id
			email = tgr.Tenant.Meta.Annotations[tutil.TagEmail]

			ctx := tutil.ContextWithProjectAndTenant(ctx, project, tgr.Tenant)

			return next(ctx, req)
		default:
			return next(ctx, req)
		}
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
