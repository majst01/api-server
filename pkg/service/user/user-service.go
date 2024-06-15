package user

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"

	putil "github.com/metal-stack/api-server/pkg/project"
	tutil "github.com/metal-stack/api-server/pkg/tenant"

	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"github.com/metal-stack/metal-lib/pkg/pointer"
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

func (u *userServiceServer) Get(ctx context.Context, _ *connect.Request[apiv1.UserServiceGetRequest]) (*connect.Response[apiv1.UserServiceGetResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
	)

	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	pat, err := GetProjectsAndTenants(ctx, u.masterClient, t.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	user := &apiv1.User{
		Login:          t.UserId,
		Name:           pat.DefaultTenant.Name,
		Email:          pat.DefaultTenant.Email,
		AvatarUrl:      pat.DefaultTenant.AvatarUrl,
		Tenants:        pat.Tenants,
		Projects:       pat.Projects,
		DefaultTenant:  pat.DefaultTenant,
		DefaultProject: pat.DefaultProject,
	}

	return connect.NewResponse(&apiv1.UserServiceGetResponse{User: user}), nil
}

type ProjectsAndTenants struct {
	Projects       []*apiv1.Project
	DefaultProject *apiv1.Project
	Tenants        []*apiv1.Tenant
	DefaultTenant  *apiv1.Tenant
	ProjectRoles   map[string]apiv1.ProjectRole
	TenantRoles    map[string]apiv1.TenantRole
}

// GetProjectsAndTenants returns all proejcts and tenants that the user is participating in
func GetProjectsAndTenants(ctx context.Context, masterClient mdc.Client, userId string) (*ProjectsAndTenants, error) {
	var (
		projectRoles   = map[string]apiv1.ProjectRole{}
		projects       []*apiv1.Project
		defaultProject *apiv1.Project

		tenantRoles   = map[string]apiv1.TenantRole{}
		tenants       []*apiv1.Tenant
		defaultTenant *apiv1.Tenant
	)

	projectResp, err := masterClient.Tenant().FindParticipatingProjects(ctx, &mdcv1.FindParticipatingProjectsRequest{TenantId: userId, IncludeInherited: pointer.Pointer(true)})
	if err != nil {
		return nil, err
	}

	tenantResp, err := masterClient.Tenant().FindParticipatingTenants(ctx, &mdcv1.FindParticipatingTenantsRequest{TenantId: userId, IncludeInherited: pointer.Pointer(true)})
	if err != nil {
		return nil, err
	}

	for _, projectWithAnnotations := range projectResp.Projects {
		p := projectWithAnnotations.Project

		apip, err := putil.ToProject(p)
		if err != nil {
			return nil, fmt.Errorf("unable to convert project %w", err)
		}

		if p.TenantId == userId && putil.IsDefaultProject(p) {
			defaultProject = apip
		}

		projects = append(projects, apip)

		var (
			projectRole = putil.ProjectRoleFromMap(projectWithAnnotations.ProjectAnnotations)
			tenantRole  = tutil.TenantRoleFromMap(projectWithAnnotations.TenantAnnotations)
		)

		switch {
		case projectRole == apiv1.ProjectRole_PROJECT_ROLE_OWNER, tenantRole == apiv1.TenantRole_TENANT_ROLE_OWNER:
			projectRole = apiv1.ProjectRole_PROJECT_ROLE_OWNER
		case projectRole == apiv1.ProjectRole_PROJECT_ROLE_EDITOR, tenantRole == apiv1.TenantRole_TENANT_ROLE_EDITOR:
			projectRole = apiv1.ProjectRole_PROJECT_ROLE_EDITOR
		case projectRole == apiv1.ProjectRole_PROJECT_ROLE_VIEWER, tenantRole == apiv1.TenantRole_TENANT_ROLE_VIEWER:
			projectRole = apiv1.ProjectRole_PROJECT_ROLE_VIEWER
		case tenantRole == apiv1.TenantRole_TENANT_ROLE_GUEST:
			// user has not access to this project, ignore
			continue
		default:
			// no roles associated with either tenant or project
			continue
		}

		projectRoles[p.Meta.GetId()] = projectRole
	}

	for _, tenantWithAnnotations := range tenantResp.Tenants {
		t := tenantWithAnnotations.Tenant

		apit := tutil.ConvertFromTenant(t)

		if t.Meta.Id == userId {
			defaultTenant = apit
		}

		tenants = append(tenants, apit)

		var (
			projectRole = putil.ProjectRoleFromMap(tenantWithAnnotations.ProjectAnnotations)
			tenantRole  = tutil.TenantRoleFromMap(tenantWithAnnotations.TenantAnnotations)
		)

		if tenantRole == apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED && projectRole > 0 {
			tenantRole = apiv1.TenantRole_TENANT_ROLE_GUEST
		}

		tenantRoles[t.Meta.GetId()] = tenantRole
	}

	if defaultProject == nil {
		return nil, fmt.Errorf("unable to find a default project for user: %s", userId)
	}
	if defaultTenant == nil {
		return nil, fmt.Errorf("unable to find a default tenant for user: %s", userId)
	}

	return &ProjectsAndTenants{
		Tenants:        tenants,
		Projects:       projects,
		DefaultTenant:  defaultTenant,
		DefaultProject: defaultProject,
		ProjectRoles:   projectRoles,
		TenantRoles:    tenantRoles,
	}, nil
}
