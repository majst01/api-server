package authentication

import "embed"

//go:embed *.rego
var Policies embed.FS
