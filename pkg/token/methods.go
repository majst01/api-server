package token

import (
	"strings"

	"github.com/google/uuid"

	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/permissions"
)

func AllowedMethods(servicePermissions *permissions.ServicePermissions, claims *Claims) MethodPermissions {
	perms := MethodPermissions{}

	for subject, role := range claims.Roles {
		if IsProjectSubject(subject) {
			switch role {
			case v1.OWNER, v1.ADMIN:
				perms[subject] = append(perms[subject], servicePermissions.Roles.Project.Owner...)
			case v1.EDITOR:
				perms[subject] = append(perms[subject], servicePermissions.Roles.Project.Editor...)
			case v1.VIEWER:
				perms[subject] = append(perms[subject], servicePermissions.Roles.Project.Viewer...)
			}
		} else {
			// subject is a tenant
			switch role {
			case v1.OWNER, v1.ADMIN:
				perms[subject] = append(perms[subject], servicePermissions.Roles.Tenant.Owner...)
			case v1.EDITOR:
				perms[subject] = append(perms[subject], servicePermissions.Roles.Tenant.Editor...)
			case v1.VIEWER:
				perms[subject] = append(perms[subject], servicePermissions.Roles.Tenant.Viewer...)
			}
		}
	}

	return perms
}

func IsAdminToken(claims *Claims) bool {
	// TODO: maybe it would make more sense to put this information into the token itself?

	if _, ok := claims.Roles["*"]; ok {
		return true
	}

	// if there is any admin method contained in the permissions, we assume the token comes from an admin
	for _, perms := range claims.Permissions {
		for _, perm := range perms {
			if strings.HasPrefix(perm, "/admin.v1") {
				return true
			}
		}
	}

	return false
}

func IsProjectSubject(subject string) bool {
	// TODO: it certainly makes sense to have a better indicator for subject than trying to parse a uuid
	_, err := uuid.Parse(subject)
	return err == nil
}
