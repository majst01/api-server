package token

import (
	"time"

	v1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type token struct {
	// Uuid of the jwt token, used to reference it by revoke
	Uuid string `json:"uuid,omitempty"`
	// UserId who created this token
	UserId string `json:"user_id,omitempty"`
	// Description is a user given description of this token.
	Description string `json:"description,omitempty"`
	// Permissions is a list of service methods this token can be used for
	Permissions []methodPermission `json:"permissions,omitempty"`
	// Expires gives the date in the future after which this token can not be used anymore
	Expires *time.Time `json:"expires,omitempty"`
	// IssuedAt gives the date when this token was created
	IssuedAt *time.Time `json:"issued_at,omitempty"`
	// TokenType describes the type of this token
	TokenType int32 `json:"token_type,omitempty"`
	// ProjectRoles associates a project id with the corresponding role of the token owner
	ProjectRoles map[string]string `json:"project_roles,omitempty"`
	// TenantRoles associates a tenant id with the corresponding role of the token owner
	TenantRoles map[string]string `json:"tenant_roles,omitempty"`
	// AdminRole defines the admin role of the token owner
	AdminRole *string `json:"admin_role,omitempty"`
}

type methodPermission struct {
	// Subject maybe either the project or the organization
	// for which the methods should be allowed
	Subject string `json:"subject,omitempty"`
	// Methods which should be accessible
	Methods []string `json:"methods,omitempty"`
}

func toInternal(t *v1.Token) *token {
	var permissions []methodPermission
	for _, p := range t.Permissions {
		permissions = append(permissions, methodPermission{
			Subject: p.Subject,
			Methods: p.Methods,
		})
	}

	var (
		projectRoles = map[string]string{}
		tenantRoles  = map[string]string{}

		expires  *time.Time
		issuedAt *time.Time

		adminRole *string
	)

	if t.Expires != nil {
		expires = pointer.Pointer(t.Expires.AsTime())
	}
	if t.IssuedAt != nil {
		issuedAt = pointer.Pointer(t.IssuedAt.AsTime())
	}

	for id, role := range t.ProjectRoles {
		projectRoles[id] = role.String()
	}
	for id, role := range t.TenantRoles {
		tenantRoles[id] = role.String()
	}

	if t.AdminRole != nil {
		adminRole = pointer.Pointer(t.AdminRole.String())
	}

	return &token{
		Uuid:         t.Uuid,
		UserId:       t.UserId,
		Description:  t.Description,
		Permissions:  permissions,
		Expires:      expires,
		IssuedAt:     issuedAt,
		TokenType:    int32(t.TokenType),
		ProjectRoles: projectRoles,
		TenantRoles:  tenantRoles,
		AdminRole:    adminRole,
	}
}

func toExternal(t *token) *v1.Token {
	var permissions []*v1.MethodPermission
	for _, p := range t.Permissions {
		permissions = append(permissions, &v1.MethodPermission{
			Subject: p.Subject,
			Methods: p.Methods,
		})
	}

	var (
		projectRoles = map[string]v1.ProjectRole{}
		tenantRoles  = map[string]v1.TenantRole{}

		expires  *timestamppb.Timestamp
		issuedAt *timestamppb.Timestamp

		adminRole *v1.AdminRole
	)

	if t.Expires != nil {
		expires = timestamppb.New(*t.Expires)
	}
	if t.IssuedAt != nil {
		issuedAt = timestamppb.New(*t.IssuedAt)
	}

	for id, role := range t.ProjectRoles {
		projectRoles[id] = v1.ProjectRole(v1.ProjectRole_value[role])
	}
	for id, role := range t.TenantRoles {
		tenantRoles[id] = v1.TenantRole(v1.TenantRole_value[role])
	}

	if t.AdminRole != nil {
		adminRole = pointer.Pointer(v1.AdminRole(v1.AdminRole_value[*t.AdminRole]))
	}

	return &v1.Token{
		Uuid:         t.Uuid,
		UserId:       t.UserId,
		Description:  t.Description,
		Permissions:  permissions,
		Expires:      expires,
		IssuedAt:     issuedAt,
		TokenType:    v1.TokenType(t.TokenType),
		ProjectRoles: projectRoles,
		TenantRoles:  tenantRoles,
		AdminRole:    adminRole,
	}
}
