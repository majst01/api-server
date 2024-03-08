package api.v1.metalstack.io.authz

import rego.v1

visibilitymethods := ["/api.v1.PublicService/List", "/api.v1.PrivateService/List"]

visibility := {"public": {"/api.v1.PublicService/List": true}, "private": {"/api.v1.PrivateService/List"}}

test_public_visibility_with_token_allowed if {
	decision.allow with input as {
		"method": "/api.v1.PublicService/List",
		"token": jwt,
		"request": {"project": "project-a"},
		"jwks": json.marshal(public),
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}

test_public_visibility_without_token_allowed if {
	decision.allow with input as {
		"method": "/api.v1.PublicService/List",
		"token": "",
		"request": {},
		"jwks": json.marshal(public),
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}

test_private_visibility_with_token_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.PrivateService/List",
		"token": jwt,
		"request": {"project": "project-a"},
		"jwks": json.marshal(public),
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}

test_private_visibility_without_token_not_allowed if {
	not decision.allow with input as {
		"method": "/api.v1.PrivateService/List",
		"token": "",
		"request": {},
		"jwks": json.marshal(public),
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}
