package api.v1.metalstack.io.authz

import rego.v1

methods := ["/api.v1.ClusterService/Get"]

admin_roles := {"ADMIN_ROLE_EDITOR": [
	"/admin.v1.ClusterService/Get",
	"/admin.v1.ClusterService/List",
]}

test_get_cluster_allowed if {
	decision.allow with input as {
		"method": "/api.v1.ClusterService/Get",
		"token": valid_jwt,
		"request": {"project": "project-a"},
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_list_clusters_not_allowed_with_wrong_permissions if {
	not decision.allow with input as {
		"method": "/api.v1.ClusterService/List",
		"request": null,
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {
			"project-d": ["/api.v1.ClusterService/Get"],
			"project-e": ["/api.v1.ClusterService/Get"],
		},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_list_clusters_not_allowed_with_wrong_jwt if {
	not decision.allow with input as {
		"method": "/api.v1.ClusterService/List",
		"request": null,
		"token": jwt_with_wrong_secret,
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_list_clusters_not_allowed_with_wrong_iss if {
	not decision.allow with input as {
		"method": "/api.v1.ClusterService/List",
		"request": null,
		"token": jwt_with_wrong_issuer,
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_list_clusters_allowed if {
	decision.allow with input as {
		"method": "/api.v1.ClusterService/List",
		"request": {"project": "project-a"},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_create_clusters_allowed if {
	decision.allow with input as {
		"method": "/api.v1.ClusterService/Create",
		"request": {"project": "project-a"},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_create_clusters_not_allowed_for_other_project if {
	not decision.allow with input as {
		"method": "/api.v1.ClusterService/Create",
		"request": {"project": "project-c"},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_is_method_allowed if {
	not is_method_allowed with input as {
		"method": "/api.v1.ClusterService/Create",
		"request": {"project": "project-c"},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
}

test_decision_reason_method_not_allowed if {
	d := decision with input as {
		"method": "/api.v1.ClusterService/List",
		"request": {"project": "project-c"},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	}
		with data.methods as methods
		with data.allowed_issuers as allowed_issuers
	not d.allow
	d.reason == "method denied or unknown:/api.v1.ClusterService/List"
}

test_decision_admin_is_allowed if {
	d := decision with input as {
		"method": "/admin.v1.ClusterService/List",
		"request": {"project": "project-c"},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"admin_role": "ADMIN_ROLE_EDITOR",
	}
		with data.roles.admin as admin_roles
		with data.allowed_issuers as allowed_issuers
	d.allow
}
