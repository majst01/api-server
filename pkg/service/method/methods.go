package method

import (
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/permissions"
)

func IsAdminToken(token *apiv1.Token) bool {
	return token.AdminRole != nil
}

func PermissionsBySubject(token *apiv1.Token) map[string]*apiv1.MethodPermission {
	res := map[string]*apiv1.MethodPermission{}
	for _, p := range token.Permissions {
		perm, ok := res[p.Subject]
		if !ok {
			perm = &apiv1.MethodPermission{
				Subject: p.Subject,
			}
		}

		perm.Methods = append(perm.Methods, p.Methods...)

		res[p.Subject] = perm
	}
	return res
}

func AllowedMethodsFromRoles(servicePermissions *permissions.ServicePermissions, token *apiv1.Token) map[string]*apiv1.MethodPermission {
	perms := map[string]*apiv1.MethodPermission{}

	for projectID, role := range token.ProjectRoles {
		perm, ok := perms[projectID]
		if !ok {
			perm = &apiv1.MethodPermission{
				Subject: projectID,
			}
		}

		perm.Methods = append(perm.Methods, servicePermissions.Roles.Project[role.String()]...)

		perms[projectID] = perm
	}

	for tenantID, role := range token.TenantRoles {
		perm, ok := perms[tenantID]
		if !ok {
			perm = &apiv1.MethodPermission{
				Subject: tenantID,
			}
		}

		perm.Methods = append(perm.Methods, servicePermissions.Roles.Tenant[role.String()]...)

		perms[tenantID] = perm
	}

	return perms
}
