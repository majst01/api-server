package api.v1.metalstack.io.authz

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

jwt := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "api-server",
		"sub": "1234567890",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"exp": (time.now_ns() / 1000000000) + 100,
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	},
	private1,
)

admin_jwt := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "api-server",
		"sub": "1234567890",
		"name": "Andrew Admin",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"exp": (time.now_ns() / 1000000000) + 100,
		"roles": {"*": "admin"},
	},
	private2,
)

jwt_with_wrong_secret := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "api-server",
		"sub": "1234567890",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"exp": (time.now_ns() / 1000000000) + 100,
		"permissions": {
			"project-a": [
				"/api.v1.ClusterService/Get",
				"/api.v1.ClusterService/List",
				"/api.v1.ClusterService/Create",
				"/api.v1.ClusterService/Update",
				"/api.v1.ClusterService/Delete",
			],
			"project-b": [
				"/api.v1.ClusterService/Get",
				"/api.v1.ClusterService/List",
				"/api.v1.ClusterService/Create",
				"/api.v1.ClusterService/Update",
				"/api.v1.ClusterService/Delete",
			],
		},
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
		"sub": "1234567890",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"exp": (time.now_ns() / 1000000000) + 100,
		"permissions": {"project-a": [
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/Get",
			"/api.v1.ClusterService/List",
			"/api.v1.ClusterService/Create",
			"/api.v1.ClusterService/Update",
			"/api.v1.ClusterService/Delete",
		]},
	},
	private1,
)

jwt_with_wrong_projects := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "api-server",
		"sub": "1234567890",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"permissions": {
			"project-d": [
				"/api.v1.ClusterService/Get",
				"/api.v1.ClusterService/List",
				"/api.v1.ClusterService/Create",
				"/api.v1.ClusterService/Update",
				"/api.v1.ClusterService/Delete",
			],
			"project-e": [
				"/api.v1.ClusterService/Get",
				"/api.v1.ClusterService/List",
				"/api.v1.ClusterService/Create",
				"/api.v1.ClusterService/Update",
				"/api.v1.ClusterService/Delete",
			],
		},
	},
	private1,
)

jwt_with_wrong_permission := io.jwt.encode_sign(
	{
		"typ": "JWT",
		"alg": "ES512",
	},
	{
		"iss": "api-server",
		"sub": "1234567890",
		"name": "John Doe",
		"iat": time.now_ns() / 1000000000,
		"nbf": (time.now_ns() / 1000000000) - 100,
		"permissions": {
			"project-d": ["/api.v1.ClusterService/Get"],
			"project-e": ["/api.v1.ClusterService/Get"],
		},
	},
	private1,
)

jwt_with_subject_owner_role := io.jwt.encode_sign(
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
		"roles": {"johndoe@github": "owner"},
	},
	private1,
)

jwt_with_non_subject_owner_role := io.jwt.encode_sign(
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
		"roles": {"johndifferent@github": "owner"},
	},
	private1,
)

jwt_with_subject_non_owner_role := io.jwt.encode_sign(
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
		"roles": {"johndoe@github": "editor"},
	},
	private1,
)

jwt_with_subject_with_self_token_list_method := io.jwt.encode_sign(
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
		"permissions": {"johndoe@github": ["/api.v1.TokenService/List"]},
	},
	private1,
)
