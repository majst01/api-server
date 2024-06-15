package token

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	apiv1 "github.com/metal-stack/api/go/api/v1"
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

// TokenRole is a mapping from subject to role there
// TODO: can be removed after migration to split project and tenant roles
// Deprecated: can be removed after migration to split project and tenant roles
type tokenRole struct {
	// Subject specifies the subject (project or organization) this role applies to
	Subject string `json:"subject,omitempty"`
	// Role defines the string representation of a tenantrole, projectrole or a global adminrole
	Role string `json:"role,omitempty"`
}

func toInternal(t *apiv1.Token) *token {
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

func toExternal(t *token) *apiv1.Token {
	var permissions []*apiv1.MethodPermission
	for _, p := range t.Permissions {
		permissions = append(permissions, &apiv1.MethodPermission{
			Subject: p.Subject,
			Methods: p.Methods,
		})
	}

	var (
		projectRoles = map[string]apiv1.ProjectRole{}
		tenantRoles  = map[string]apiv1.TenantRole{}

		expires  *timestamppb.Timestamp
		issuedAt *timestamppb.Timestamp

		adminRole *apiv1.AdminRole
	)

	if t.Expires != nil {
		expires = timestamppb.New(*t.Expires)
	}
	if t.IssuedAt != nil {
		issuedAt = timestamppb.New(*t.IssuedAt)
	}

	for id, role := range t.ProjectRoles {
		projectRoles[id] = apiv1.ProjectRole(apiv1.ProjectRole_value[role])
	}
	for id, role := range t.TenantRoles {
		tenantRoles[id] = apiv1.TenantRole(apiv1.TenantRole_value[role])
	}

	if t.AdminRole != nil {
		adminRole = pointer.Pointer(apiv1.AdminRole(apiv1.AdminRole_value[*t.AdminRole]))
	}

	return &apiv1.Token{
		Uuid:         t.Uuid,
		UserId:       t.UserId,
		Description:  t.Description,
		Permissions:  permissions,
		Expires:      expires,
		IssuedAt:     issuedAt,
		TokenType:    apiv1.TokenType(t.TokenType),
		ProjectRoles: projectRoles,
		TenantRoles:  tenantRoles,
		AdminRole:    adminRole,
	}
}

// TODO: this can be removed after migration
type tokenCompat struct {
	// Uuid of the jwt token, used to reference it by revoke
	Uuid string `json:"uuid,omitempty"`
	// UserId who created this token
	UserId string `json:"user_id,omitempty"`
	// Description is a user given description of this token.
	Description string `json:"description,omitempty"`
	// Permissions is a list of service methods this token can be used for
	Permissions []methodPermission `json:"permissions,omitempty"`
	// Expires gives the date in the future after which this token can not be used anymore
	Expires *timestamppb.Timestamp `json:"expires,omitempty"`
	// IssuedAt gives the date when this token was created
	IssuedAt *timestamppb.Timestamp `json:"issued_at,omitempty"`
	// TokenType describes the type of this token
	TokenType int32 `json:"token_type,omitempty"`
	// Deprecated: can be removed after migration to split project and tenant roles
	Roles []*tokenRole `json:"roles,omitempty"`
}

// TODO: this can be removed after migration
func compat(oldToken []byte) (token, error) {
	var (
		isProjectSubject = func(subject string) bool {
			_, err := uuid.Parse(subject)
			return err == nil
		}

		projectRoles = map[string]string{}
		tenantRoles  = map[string]string{}

		adminRole *string
	)

	old := tokenCompat{}

	err := json.Unmarshal(oldToken, &old)
	if err != nil {
		return token{}, err
	}

	var permissions []methodPermission
	for _, p := range old.Permissions {
		permissions = append(permissions, methodPermission{
			Subject: p.Subject,
			Methods: p.Methods,
		})
	}

	for _, role := range old.Roles {
		if role.Role == "admin" && role.Subject == "*" {
			adminRole = pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR.String())
			continue
		}

		if isProjectSubject(role.Subject) {

			var projectRole apiv1.ProjectRole

			switch role.Role {
			case "admin", "owner":
				projectRole = apiv1.ProjectRole_PROJECT_ROLE_OWNER
			case "editor":
				projectRole = apiv1.ProjectRole_PROJECT_ROLE_EDITOR
			case "viewer":
				projectRole = apiv1.ProjectRole_PROJECT_ROLE_VIEWER
			default:
				projectRole = apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED
			}

			projectRoles[role.Subject] = projectRole.String()

			continue
		}

		var tenantRole apiv1.TenantRole

		switch role.Role {
		case "admin", "owner":
			tenantRole = apiv1.TenantRole_TENANT_ROLE_OWNER
		case "editor":
			tenantRole = apiv1.TenantRole_TENANT_ROLE_EDITOR
		case "viewer":
			tenantRole = apiv1.TenantRole_TENANT_ROLE_VIEWER
		default:
			tenantRole = apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED
		}

		tenantRoles[role.Subject] = tenantRole.String()
	}

	return token{
		Uuid:         old.Uuid,
		UserId:       old.UserId,
		Description:  old.Description,
		Permissions:  permissions,
		Expires:      pointer.Pointer(old.Expires.AsTime()),
		IssuedAt:     pointer.Pointer(old.IssuedAt.AsTime()),
		TokenType:    old.TokenType,
		ProjectRoles: projectRoles,
		TenantRoles:  tenantRoles,
		AdminRole:    adminRole,
	}, nil
}
