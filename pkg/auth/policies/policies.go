package policies

import "embed"

//go:embed *.rego
var RegoPolicies embed.FS
