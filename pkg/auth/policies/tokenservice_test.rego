package api.v1.metalstack.io.authz

import rego.v1

tokenmethods := ["/api.v1.TokenService/List", "/api.v1.TokenService/Create"]

tokenvisibility := {"self": {
	"/api.v1.TokenService/List": true,
	"/api.v1.TokenService/Create": true,
}}

test_self_method_for_owner_role_allowed if {
	decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"tenant_roles": {"johndoe@github": "TENANT_ROLE_OWNER"},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_self_method_for_different_role_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"tenant_roles": {"johndoe@github": "TENANT_ROLE_EDITOR"},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_self_method_for_wrong_owner_role_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"tenant_roles": {"johndifferent@github": "TENANT_ROLE_OWNER"},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_self_method_for_method_permission_allowed if {
	decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"johndoe@github": ["/api.v1.TokenService/List"]},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_method_for_not_included_method_permission_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.TokenService/Revoke",
		"request": {},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"johndoe@github": ["/api.v1.TokenService/List"]},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

# TokenService Create has visibility self, the token does not include this in the permissions
# but is allowed because of at least a permission is given because the service checks for proper permissions
test_self_method_for_not_included_method_permission_allowed if {
	decision.allow with input as {
		"method": "/api.v1.TokenService/Create",
		"request": {},
		"token": valid_jwt,
		"jwks": json.marshal(public),
		"permissions": {"johndoe@github": ["/api.v1.TokenService/List"]},
	}
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}
