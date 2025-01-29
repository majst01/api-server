package api.v1.metalstack.io.authorization_test

import data.api.v1.metalstack.io.authorization
import rego.v1

visibilitymethods := ["/metalstack.api.v1.PublicService/List"]

visibility := {"public": {"/metalstack.api.v1.PublicService/List": true}}

test_public_visibility_with_token_allowed if {
	authorization.decision.allow with input as {
		"method": "/metalstack.api.v1.PublicService/List",
		"token": tokenv1,
		"request": {"project": "project-a"},
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}

test_public_visibility_without_token_allowed if {
	authorization.decision.allow with input as {
		"method": "/metalstack.api.v1.PublicService/List",
		"token": null,
		"request": {},
	}
		with data.methods as visibilitymethods
		with data.visibility as visibility
}
