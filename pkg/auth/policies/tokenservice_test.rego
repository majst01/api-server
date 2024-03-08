package api.v1.metalstack.io.authz

import rego.v1

tokenroles := {"tenant": {}, "project": {}}

tokenmethods := ["/api.v1.TokenService/List", "/api.v1.TokenService/Create"]

tokenvisibility := {"self": {
	"/api.v1.TokenService/List": true,
	"/api.v1.TokenService/Create": true,
}}

test_self_method_for_owner_role_allowed if {
	decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": jwt_with_subject_owner_role,
		"jwks": json.marshal(public),
	}
		with data.roles as tokenroles
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_self_method_for_different_role_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": jwt_with_subject_non_owner_role,
		"jwks": json.marshal(public),
	}
		with data.roles as tokenroles
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_self_method_for_wrong_owner_role_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": jwt_with_non_subject_owner_role,
		"jwks": json.marshal(public),
	}
		with data.roles as tokenroles
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_self_method_for_method_permission_allowed if {
	decision.allow with input as {
		"method": "/api.v1.TokenService/List",
		"request": {},
		"token": jwt_with_subject_with_self_token_list_method,
		"jwks": json.marshal(public),
	}
		with data.roles as tokenroles
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}

test_method_for_not_included_method_permission_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.TokenService/Revoke",
		"request": {},
		"token": jwt_with_subject_with_self_token_list_method,
		"jwks": json.marshal(public),
	}
		with data.roles as tokenroles
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
		"token": jwt_with_subject_with_self_token_list_method,
		"jwks": json.marshal(public),
	}
		with data.roles as tokenroles
		with data.methods as tokenmethods
		with data.visibility as tokenvisibility
		with data.allowed_issuers as allowed_issuers
}
