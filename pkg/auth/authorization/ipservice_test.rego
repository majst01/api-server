package api.v1.metalstack.io.authorization

import rego.v1

methods := ["/api.v1.IPService/Get"]

admin_roles := {"ADMIN_ROLE_EDITOR": [
	"/admin.v1.IPService/Get",
	"/admin.v1.IPService/List",
]}

test_get_ip_allowed if {
	decision.allow with input as {
		"method": "/api.v1.IPService/Get",
		"token": tokenv1,
		"request": {"project": "project-a"},
		"permissions": {"project-a": [
			"/api.v1.IPService/Get",
			"/api.v1.IPService/Get",
			"/api.v1.IPService/List",
			"/api.v1.IPService/Create",
			"/api.v1.IPService/Update",
			"/api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_list_ips_not_allowed_with_wrong_permissions if {
	not decision.allow with input as {
		"method": "/api.v1.IPService/List",
		"request": null,
		"token": tokenv1,
		"permissions": {
			"project-d": ["/api.v1.IPService/Get"],
			"project-e": ["/api.v1.IPService/Get"],
		},
	}
		with data.methods as methods
}

test_list_ips_allowed if {
	decision.allow with input as {
		"method": "/api.v1.IPService/List",
		"request": {"project": "project-a"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/api.v1.IPService/Get",
			"/api.v1.IPService/Get",
			"/api.v1.IPService/List",
			"/api.v1.IPService/Create",
			"/api.v1.IPService/Update",
			"/api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_create_ips_allowed if {
	decision.allow with input as {
		"method": "/api.v1.IPService/Create",
		"request": {"project": "project-a"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/api.v1.IPService/Get",
			"/api.v1.IPService/Get",
			"/api.v1.IPService/List",
			"/api.v1.IPService/Create",
			"/api.v1.IPService/Update",
			"/api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_create_ips_not_allowed_for_other_project if {
	not decision.allow with input as {
		"method": "/api.v1.IPService/Create",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/api.v1.IPService/Get",
			"/api.v1.IPService/Get",
			"/api.v1.IPService/List",
			"/api.v1.IPService/Create",
			"/api.v1.IPService/Update",
			"/api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_is_method_allowed if {
	not is_method_allowed with input as {
		"method": "/api.v1.IPService/Create",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/api.v1.IPService/Get",
			"/api.v1.IPService/Get",
			"/api.v1.IPService/List",
			"/api.v1.IPService/Create",
			"/api.v1.IPService/Update",
			"/api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_decision_reason_method_not_allowed if {
	d := decision with input as {
		"method": "/api.v1.IPService/List",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/api.v1.IPService/Get",
			"/api.v1.IPService/Get",
			"/api.v1.IPService/List",
			"/api.v1.IPService/Create",
			"/api.v1.IPService/Update",
			"/api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
	not d.allow
	d.reason == "method denied or unknown: /api.v1.IPService/List"
}

test_decision_admin_is_allowed if {
	d := decision with input as {
		"method": "/admin.v1.IPService/List",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"admin_role": "ADMIN_ROLE_EDITOR",
	}
		with data.roles.admin as admin_roles
	d.allow
}
