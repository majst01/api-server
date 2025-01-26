package api.v1.metalstack.io.authentication

import rego.v1

default decision := {"valid": false, "reason": "invalid token"}

# METADATA
# description: Allow tokens if they are valid
# entrypoint: true
decision := {"valid": true, "subject": token.sub, "id": token.jti} if {
	has_valid_signature
	has_valid_token_issuer(token, data.allowed_issuers)
	has_valid_token_duration(token)
}

# use this for debugging:
# print("valid", true, "payload", token, "jwks", input.jwks)

decision := {"valid": false, "reason": reason} if {
	# We even treat tokens without a valid signature as expired.
	# The root certificate might have been removed by certificate rotation
	# and is not available for verification anymore.
	has_valid_token_issuer(token, data.allowed_issuers)
	not has_valid_token_duration(token)
	reason := "token has expired"
}

decision := {"valid": false, "reason": reason} if {
	has_valid_signature
	not has_valid_token_issuer(token, data.allowed_issuers)
	has_valid_token_duration(token)
	reason := sprintf("invalid token issuer: %s", [token.iss])
}

has_valid_token_duration(token) if {
	now := time.now_ns() / 1000000000
	token.nbf <= now
	token.exp > now
}

has_valid_token_issuer(token, allowed_issuers) if {
	token.iss in allowed_issuers
}

has_valid_signature if {
	io.jwt.verify_es512(input.token, input.jwks)
}

token := payload if {
	[_, payload, _] := io.jwt.decode(input.token)
}
