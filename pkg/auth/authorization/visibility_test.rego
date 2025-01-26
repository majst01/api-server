package api.v1.metalstack.io.authorization

import rego.v1

visibilitymethods := ["/api.v1.PublicService/List"]

visibility := {"public": {"/api.v1.PublicService/List": true}}

test_public_visibility_with_token_allowed if {
	decision.allow with input as {
		"method": "/api.v1.PublicService/List",
		"token": tokenv1,
		"request": {"project": "project-a"},
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}

test_public_visibility_without_token_allowed if {
	decision.allow with input as {
		"method": "/api.v1.PublicService/List",
		"token": null,
		"request": {},
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}
