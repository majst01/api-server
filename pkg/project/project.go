package project

import (
	"context"
	"fmt"
	"strconv"

	"connectrpc.com/connect"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
)

const (
	DefaultProjectAnnotation = "metal-stack.io/default-project"
	ProjectRoleAnnotation    = "metalstack.cloud/project-role"
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
	return &apiv1.Project{
		Uuid:             p.Meta.Id,
		Name:             p.Name,
		Description:      p.Description,
		Tenant:           p.TenantId,
		IsDefaultProject: IsDefaultProject(p),
		CreatedAt:        p.Meta.CreatedTime,
		UpdatedAt:        p.Meta.UpdatedTime,
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
