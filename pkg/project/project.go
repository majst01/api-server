package project

import (
	"context"
	"fmt"
	"strconv"

	"connectrpc.com/connect"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	apiv1 "github.com/metal-stack/api/go/metalstack/api/v1"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
)

const (
	DefaultProjectAnnotation = "metal-stack.io/default-project"
	ProjectRoleAnnotation    = "metalstack.cloud/project-role"
	AvatarURLAnnotation      = "avatarUrl"
)

func ProjectRoleFromMap(annotations map[string]string) apiv1.ProjectRole {
	if annotations == nil {
		return apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED
	}

	var (
		annotation  = annotations[ProjectRoleAnnotation]
		projectRole = apiv1.ProjectRole(apiv1.ProjectRole_value[annotation])
	)

	return projectRole
}

func ToProject(p *mdcv1.Project) (*apiv1.Project, error) {
	if p.Meta == nil {
		return nil, fmt.Errorf("project meta is nil")
	}
	avatarUrl := p.Meta.Annotations[AvatarURLAnnotation]

	return &apiv1.Project{
		Uuid:             p.Meta.Id,
		Name:             p.Name,
		Description:      p.Description,
		Tenant:           p.TenantId,
		IsDefaultProject: IsDefaultProject(p),
		CreatedAt:        p.Meta.CreatedTime,
		UpdatedAt:        p.Meta.UpdatedTime,
		AvatarUrl:        &avatarUrl,
	}, nil
}

func IsDefaultProject(p *mdcv1.Project) bool {
	value, ok := p.Meta.Annotations[DefaultProjectAnnotation]
	if !ok {
		return false
	}

	res, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}

	return res
}

func GetProjectMember(ctx context.Context, c mdc.Client, projectID, tenantID string) (*mdcv1.ProjectMember, *mdcv1.Project, error) {
	getResp, err := c.Project().Get(ctx, &mdcv1.ProjectGetRequest{
		Id: projectID,
	})
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, fmt.Errorf("no project found with id %q: %w", projectID, err))
	}

	memberships, err := c.ProjectMember().Find(ctx, &mdcv1.ProjectMemberFindRequest{
		ProjectId: &projectID,
		TenantId:  &tenantID,
	})
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, err)
	}

	switch len(memberships.ProjectMembers) {
	case 0:
		return nil, nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("tenant %s is not a member of project %s", tenantID, projectID))
	case 1:
		// fallthrough
	default:
		return nil, nil, connect.NewError(connect.CodeInternal, fmt.Errorf("found multiple membership associations for a member to a project"))
	}

	return memberships.GetProjectMembers()[0], getResp.Project, nil
}

func GetProject(ctx context.Context, c mdc.Client, projectID string) (*mdcv1.Project, error) {
	getResp, err := c.Project().Get(ctx, &mdcv1.ProjectGetRequest{
		Id: projectID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("no Tenant found with id %q: %w", projectID, err))
	}

	return getResp.Project, nil
}

type ProjectsAndTenants struct {
	Projects       []*apiv1.Project
	DefaultProject *apiv1.Project
	Tenants        []*apiv1.Tenant
	DefaultTenant  *apiv1.Tenant
	ProjectRoles   map[string]apiv1.ProjectRole
	TenantRoles    map[string]apiv1.TenantRole
}

// GetProjectsAndTenants returns all projects and tenants that the user is participating in
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

		apip, err := ToProject(p)
		if err != nil {
			return nil, fmt.Errorf("unable to convert project %w", err)
		}

		if p.TenantId == userId && IsDefaultProject(p) {
			defaultProject = apip
		}

		projects = append(projects, apip)

		var (
			projectRole = ProjectRoleFromMap(projectWithAnnotations.ProjectAnnotations)
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
			// user has no access to this project, ignore
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
			projectRole = ProjectRoleFromMap(tenantWithAnnotations.ProjectAnnotations)
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
