package user

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"

	putil "github.com/metal-stack/api-server/pkg/project"

	"github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
)

type Config struct {
	Log          *slog.Logger
	MasterClient mdc.Client
}

type userServiceServer struct {
	log          *slog.Logger
	masterClient mdc.Client
}

func New(config *Config) apiv1connect.UserServiceHandler {
	return &userServiceServer{
		log:          config.Log,
		masterClient: config.MasterClient,
	}
}

func (u *userServiceServer) Get(ctx context.Context, _ *connect.Request[v1.UserServiceGetRequest]) (*connect.Response[v1.UserServiceGetResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
	)

	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	projectsAndTenants, err := putil.GetProjectsAndTenants(ctx, u.masterClient, t.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	user := &v1.User{
		Login:          t.UserId,
		Name:           projectsAndTenants.DefaultTenant.Name,
		Email:          projectsAndTenants.DefaultTenant.Email,
		AvatarUrl:      projectsAndTenants.DefaultTenant.AvatarUrl,
		Tenants:        projectsAndTenants.Tenants,
		Projects:       projectsAndTenants.Projects,
		DefaultTenant:  projectsAndTenants.DefaultTenant,
		DefaultProject: projectsAndTenants.DefaultProject,
	}

	return connect.NewResponse(&v1.UserServiceGetResponse{User: user}), nil
}
