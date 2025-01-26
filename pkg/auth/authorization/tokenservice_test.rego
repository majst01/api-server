package api.v1.metalstack.io.authorization_test

import data.api.v1.metalstack.io.authorization
import rego.v1

tokenmethods := ["/api.v1.TokenService/List", "/api.v1.TokenService/Create"]

tokenvisibility := {"self": {
	"/api.v1.TokenService/List": true,
	"/api.v1.TokenService/Create": true,
}}

test_self_method_for_owner_role_allowed if {
	authorization.decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": tokenv1,
		"tenant_roles": {"johndoe@github": "TENANT_ROLE_OWNER"},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
}

test_self_method_for_different_role_not_allowed if {
	not authorization.decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": tokenv1,
		"tenant_roles": {"johndoe@github": "TENANT_ROLE_EDITOR"},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
}

test_self_method_for_wrong_owner_role_not_allowed if {
	not authorization.decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": tokenv1,
		"tenant_roles": {"johndifferent@github": "TENANT_ROLE_OWNER"},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
}

test_self_method_for_method_permission_allowed if {
	authorization.decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": tokenv1,
		"permissions": {"johndoe@github": ["/api.v1.TokenService/List"]},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
}

test_method_for_not_included_method_permission_not_allowed if {
	not authorization.decision.allow with input as {
		"method": "/api.v1.TokenService/Revoke",
		"request": {},
		"token": tokenv1,
		"permissions": {"johndoe@github": ["/api.v1.TokenService/List"]},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
}

# TokenService Create has visibility self, the token does not include this in the permissions
# but is allowed because of at least a permission is given because the service checks for proper permissions
test_self_method_for_not_included_method_permission_allowed if {
	authorization.decision.allow with input as {
		"method": "/api.v1.TokenService/Create",
		"request": {},
		"token": tokenv1,
		"permissions": {"johndoe@github": ["/api.v1.TokenService/List"]},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
}
