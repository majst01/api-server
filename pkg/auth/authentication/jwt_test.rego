package api.v1.metalstack.io.authentication_test

import data.api.v1.metalstack.io.authentication
import rego.v1

private1 := {
	"crv": "P-521",
	"d": "AeF2jbQXdXmPZbTMeJlqVTtBSCbQTUwFaB0bmmm5fICyLqOBT50NOz4_O8mnPkSqXcpjZI9dfINWZIvfd3Y05hPI",
	"kty": "EC",
	"x": "AdU1RbWvBImgx1HZqdY3uhrhPPAnRu-UFFn7vPYsDEzPI6uifNk9rSXIYtlfjo_Rsxcrw0NS31evdwHbn7y-ro7w",
	"y": "AdmwLz0p1hAH3zZhhcvY2y8rUbd6TMR0xDzvrsxnoKEupiwSj9HP-aGMgVnZrg6ZQXzirNgWuvKlWvldRtQGwRz4",
}

private2 := {
	"crv": "P-521",
	"d": "Ab1JgNFEaFsgZUaiFgRm8wRnWrpfIGReRyv2m_z30c6EEpkJ9UV5tciIxhPm4YYOz2G2PNoKVYAvL57MQCrasc31",
	"kty": "EC",
	"x": "ADv0gobyrZNaYsvQ4bk5Kru--ZDvZzW3WhUK96mlLqC6S-jwTguk5Qvi9eu0bARCPM64UkOginMWKjOVh1LVVWXq",
	"y": "AQafSmxsXYvEIwx05GOjICBPjYp3xfAUdO2tCRviDNWyQ8YcvcPDEZ8sNO8BgbVvMv3Xcez9L2XJ2vlVtaLOF3EO",
}

public := {"keys": [
	{
		"crv": "P-521",
		"kty": "EC",
		"x": "AdU1RbWvBImgx1HZqdY3uhrhPPAnRu-UFFn7vPYsDEzPI6uifNk9rSXIYtlfjo_Rsxcrw0NS31evdwHbn7y-ro7w",
		"y": "AdmwLz0p1hAH3zZhhcvY2y8rUbd6TMR0xDzvrsxnoKEupiwSj9HP-aGMgVnZrg6ZQXzirNgWuvKlWvldRtQGwRz4",
	},
	{
		"crv": "P-521",
		"kty": "EC",
		"x": "ADv0gobyrZNaYsvQ4bk5Kru--ZDvZzW3WhUK96mlLqC6S-jwTguk5Qvi9eu0bARCPM64UkOginMWKjOVh1LVVWXq",
		"y": "AQafSmxsXYvEIwx05GOjICBPjYp3xfAUdO2tCRviDNWyQ8YcvcPDEZ8sNO8BgbVvMv3Xcez9L2XJ2vlVtaLOF3EO",
	},
]}

allowed_issuers := ["cloud", "api-server"]

valid_jwt := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "api-server",
		"sub": "johndoe@github",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"exp": (time.now_ns() / 1000000000) + 100,
	},
	private1,
)

jwt_with_wrong_secret := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "api-server",
		"sub": "johndoe@github",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"exp": (time.now_ns() / 1000000000) + 100,
	},
	private1,
)

jwt_with_wrong_issuer := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "someone-evil",
		"sub": "johndoe@github",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"exp": (time.now_ns() / 1000000000) + 100,
	},
	private1,
)

test_token_expired if {
	d := authentication.decision with input as {
		"token": io.jwt.encode_sign(
			{
				"typ": "JWT",
				"alg": "ES512",
			},
			{
				"iss": "api-server",
				"sub": "johndoe@github",
				"name": "John Doe",
				"iat": time.now_ns() / 1000000000,
				"nbf": (time.now_ns() / 1000000000) - 100000,
				"exp": (time.now_ns() / 1000000000) - 10000,
			},
			private1,
		),
		"jwks": json.marshal(public),
	}
		with data.allowed_issuers as allowed_issuers

	not d.valid
	d.reason == "token has expired"
}

test_invalid_issuer if {
	d := authentication.decision with input as {
		"token": io.jwt.encode_sign(
			{
				"typ": "JWT",
				"alg": "ES512",
			},
			{
				"iss": "someone-evil",
				"sub": "johndoe@github",
				"name": "John Doe",
				"iat": time.now_ns() / 1000000000,
				"nbf": (time.now_ns() / 1000000000) - 100000,
				"exp": (time.now_ns() / 1000000000) + 10000,
			},
			private1,
		),
		"jwks": json.marshal(public),
	}
		with data.allowed_issuers as allowed_issuers

	not d.valid
	d.reason == "invalid token issuer: someone-evil"
}

test_expired_token_and_invalid_issuer if {
	d := authentication.decision with input as {
		"token": io.jwt.encode_sign(
			{
				"typ": "JWT",
				"alg": "ES512",
			},
			{
				"iss": "someone-evil",
				"sub": "johndoe@github",
				"name": "John Doe",
				"iat": time.now_ns() / 1000000000,
				"nbf": (time.now_ns() / 1000000000) - 100000,
				"exp": (time.now_ns() / 1000000000) - 10000,
			},
			private1,
		),
		"jwks": json.marshal(public),
	}
		with data.allowed_issuers as allowed_issuers

	not d.valid
	d.reason == "invalid token"
}

test_valid_token if {
	d := authentication.decision with input as {
		"token": io.jwt.encode_sign(
			{
				"typ": "JWT",
				"alg": "ES512",
			},
			{
				"iss": "api-server",
				"sub": "johndoe@github",
				"name": "John Doe",
				"jti": "91515033-8f6b-4543-ae44-5ccf2b47e3c5",
				"iat": time.now_ns() / 1000000000,
				"nbf": (time.now_ns() / 1000000000) - 100000,
				"exp": (time.now_ns() / 1000000000) + 10000,
			},
			private1,
		),
		"jwks": json.marshal(public),
	}
		with data.allowed_issuers as allowed_issuers

	d.valid
	d.subject == "johndoe@github"
	d.id == "91515033-8f6b-4543-ae44-5ccf2b47e3c5"
}
