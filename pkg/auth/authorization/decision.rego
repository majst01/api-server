package api.v1.metalstack.io.authorization

import rego.v1

default decision := {"allow": false}

# METADATA
# description: Prevent API access if permissions are not sufficient
# entrypoint: true
decision := {"allow": false, "reason": reason} if {
	# preconditions to avoid multiple rule matches
	not is_admin
	not service_allowed
	not is_public_service
	not is_self_service

	# actual implementation
	not is_method_allowed
	reason := sprintf("method denied or unknown: %s", [input.method])
}

decision := {"allow": true} if {
	service_allowed
}

decision := {"allow": true} if {
	is_public_service
}

decision := {"allow": false, "reason": reason} if {
	not is_admin
	reason := sprintf("access to %s not allowed", input.method)
}

decision := {"allow": true} if {
	is_admin
}

is_method_allowed if {
	# this can be used for debugging:
	# print("input method", input.method, "allowed methods", data.methods)
	data.methods[input.method] == true
}

# Rules per Service
service_allowed if {
	input.method in input.permissions[input.request.project]
}

service_allowed if {
	# role of given project must provide methods where the actual method is contained
	input.method in data.roles.project[input.project_roles[input.request.project]]
}

service_allowed if {
	input.method in data.roles.tenant[input.tenant_roles[input.request.login]]
}

# Requests to methods with visibility self
# endpoint is one of the visibility.Self methods
service_allowed if {
	is_self_service

	not input.permissions # if no permissions given (that means the key does not exist at all!), we only respect roles
	input.tenant_roles[input.token.user_id] == "TENANT_ROLE_OWNER" # only owner role may visit self
}

service_allowed if {
	is_self_service

	# if no tenant or project roles given (that means the key does not exist at all!), we only respect permissions
	not input.project_roles
	not input.tenant_roles
	input.permissions # this key exists!
}

is_public_service if {
	data.visibility.public[input.method]
}

is_self_service if {
	data.visibility.self[input.method]
}

is_admin if {
	input.admin_role
	input.method in data.roles.admin[input.admin_role]
}

is_admin if {
	input.admin_role
	is_self_service
}

is_admin if {
	input.admin_role == "ADMIN_ROLE_EDITOR"
	input.method in data.roles.project.PROJECT_ROLE_OWNER
}

is_admin if {
	input.admin_role == "ADMIN_ROLE_EDITOR"
	input.method in data.roles.tenant.TENANT_ROLE_OWNER
}

is_admin if {
	input.admin_role == "ADMIN_ROLE_VIEWER"
	input.method in data.roles.project.PROJECT_ROLE_VIEWER
}

is_admin if {
	input.admin_role == "ADMIN_ROLE_VIEWER"
	input.method in data.roles.tenant.TENANT_ROLE_VIEWER
}
