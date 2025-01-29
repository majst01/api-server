package api.v1.metalstack.io.authorization_test

import data.api.v1.metalstack.io.authorization
import rego.v1

methods := ["/metalstack.api.v1.IPService/Get"]

admin_roles := {"ADMIN_ROLE_EDITOR": [
	"/metalstack.admin.v1.IPService/Get",
	"/metalstack.admin.v1.IPService/List",
]}

test_get_ip_allowed if {
	authorization.decision.allow with input as {
		"method": "/metalstack.api.v1.IPService/Get",
		"token": tokenv1,
		"request": {"project": "project-a"},
		"permissions": {"project-a": [
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/List",
			"/metalstack.api.v1.IPService/Create",
			"/metalstack.api.v1.IPService/Update",
			"/metalstack.api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_list_ips_not_allowed_with_wrong_permissions if {
	not authorization.decision.allow with input as {
		"method": "/metalstack.api.v1.IPService/List",
		"request": null,
		"token": tokenv1,
		"permissions": {
			"project-d": ["/metalstack.api.v1.IPService/Get"],
			"project-e": ["/metalstack.api.v1.IPService/Get"],
		},
	}
		with data.methods as methods
}

test_list_ips_allowed if {
	authorization.decision.allow with input as {
		"method": "/metalstack.api.v1.IPService/List",
		"request": {"project": "project-a"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/List",
			"/metalstack.api.v1.IPService/Create",
			"/metalstack.api.v1.IPService/Update",
			"/metalstack.api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_create_ips_allowed if {
	authorization.decision.allow with input as {
		"method": "/metalstack.api.v1.IPService/Create",
		"request": {"project": "project-a"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/List",
			"/metalstack.api.v1.IPService/Create",
			"/metalstack.api.v1.IPService/Update",
			"/metalstack.api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_create_ips_not_allowed_for_other_project if {
	not authorization.decision.allow with input as {
		"method": "/metalstack.api.v1.IPService/Create",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/List",
			"/metalstack.api.v1.IPService/Create",
			"/metalstack.api.v1.IPService/Update",
			"/metalstack.api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_is_method_allowed if {
	not authorization.is_method_allowed with input as {
		"method": "/metalstack.api.v1.IPService/Create",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/List",
			"/metalstack.api.v1.IPService/Create",
			"/metalstack.api.v1.IPService/Update",
			"/metalstack.api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
}

test_decision_reason_method_not_allowed if {
	d := authorization.decision with input as {
		"method": "/metalstack.api.v1.IPService/List",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"permissions": {"project-a": [
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/Get",
			"/metalstack.api.v1.IPService/List",
			"/metalstack.api.v1.IPService/Create",
			"/metalstack.api.v1.IPService/Update",
			"/metalstack.api.v1.IPService/Delete",
		]},
	}
		with data.methods as methods
	not d.allow
	d.reason == "method denied or unknown: /metalstack.api.v1.IPService/List"
}

test_decision_admin_is_allowed if {
	d := authorization.decision with input as {
		"method": "/metalstack.admin.v1.IPService/List",
		"request": {"project": "project-c"},
		"token": tokenv1,
		"admin_role": "ADMIN_ROLE_EDITOR",
	}
		with data.roles.admin as admin_roles
	d.allow
}
