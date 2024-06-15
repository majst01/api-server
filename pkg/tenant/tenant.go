package v1

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
)

type (
	projectAndTenant struct {
		p *mdcv1.Project
		t *mdcv1.Tenant
	}

	projectAndTenantKey struct{}
)

const (
	TagEmail       = "metal-stack.io/email"
	TagPhoneNumber = "metal-stack.io/phone"
	TagAvatarURL   = "metal-stack.io/avatarurl"
	TagCreator     = "metal-stack.io/creator"

	TenantRoleAnnotation = "metalstack.cloud/tenant-role"
)

func TenantRoleFromMap(annotations map[string]string) apiv1.TenantRole {
	if annotations == nil {
		return apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED
	}

	var (
		annotation = annotations[TenantRoleAnnotation]
		tenantRole = apiv1.TenantRole(apiv1.TenantRole_value[annotation])
	)

	return tenantRole
}

func Convert(t *apiv1.Tenant) *mdcv1.Tenant {
	ann := map[string]string{
		TagEmail:     t.Email,
		TagAvatarURL: t.AvatarUrl,
	}

	return &mdcv1.Tenant{
		Meta: &mdcv1.Meta{
			Id:          t.Login,
			Kind:        "Tenant",
			Annotations: ann,
		},
		Name:        t.Name,
		Description: t.Description,
	}
}

func ConvertFromTenant(t *mdcv1.Tenant) *apiv1.Tenant {
	ann := t.Meta.Annotations
	email := ann[TagEmail]
	avatarURL := ann[TagAvatarURL]

	tenant := &apiv1.Tenant{
		Login:       t.Meta.Id,
		Name:        t.Name,
		Description: t.Description,
		Email:       email,
		AvatarUrl:   avatarURL,
		CreatedAt:   t.Meta.CreatedTime,
		UpdatedAt:   t.Meta.UpdatedTime,
	}

	return tenant
}

// ContextWithProjectAndTenant stores project and tenant in the context
// this should be called early in a request interceptor.
func ContextWithProjectAndTenant(ctx context.Context, project *mdcv1.Project, tenant *mdcv1.Tenant) context.Context {
	return context.WithValue(ctx, projectAndTenantKey{}, projectAndTenant{p: project, t: tenant})
}

// ProjectAndTenantFromContext retrieves project and tenant and ok from the context
// if previously stored by calling ContextWithProjectAndTenant.
func ProjectAndTenantFromContext(ctx context.Context) (project *mdcv1.Project, tenant *mdcv1.Tenant, ok bool) {
	value := ctx.Value(projectAndTenantKey{})

	projectAndTenant, ok := value.(projectAndTenant)
	if ok {
		return projectAndTenant.p, projectAndTenant.t, true
	}
	return nil, nil, ok
}

func GetTenantMember(ctx context.Context, c mdc.Client, tenantID, memberID string) (*mdcv1.TenantMember, error) {
	memberships, err := c.TenantMember().Find(ctx, &mdcv1.TenantMemberFindRequest{
		MemberId: &memberID,
		TenantId: &tenantID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	switch len(memberships.TenantMembers) {
	case 0:
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("tenant %s is not a member of tenant %s", tenantID, memberID))
	case 1:
		// fallthrough
	default:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("found multiple membership associations for a member to a tenant"))
	}

	return memberships.GetTenantMembers()[0], nil
}
