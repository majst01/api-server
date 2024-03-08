package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/api/v1"
	adminv1 "github.com/metal-stack/api/go/admin/v1"
	"github.com/metal-stack/metal-lib/pkg/testcommon"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	maliciousSigningKey = `{
	"keys": [
	  {
		"crv": "P-521",
		"kty": "EC",
		"x": "AZLnOqs2_5vwQ4rPGTtqOG1Y8TeIy4FgYtuRmMPfJwlTc1D4IikSX601m4sSf0xoBc1QczEmg-4i1pfpMFc1EiEe",
		"y": "AVg-GzpI-0NPGjbZalwxLb7Jeg6-1xvEXHTLdAHl6O5yiQ6t_FN28KClid-FVISc8wCdTl2B8WRny12a1Gx-f_Wq"
	  },
	  {
		"crv": "P-521",
		"kty": "EC",
		"x": "AT-6YSzYdc1VT8osBMXKn268WdbGyr3-0xdNJnEtg5FGFpwUgBmPYZKZRg2BbEdQUcWjHAKvDF4wRYA9-HmcRbzr",
		"y": "AAY7-8N4ze2bfJuCxSMyl6nihAaGe7c2r8TNAatE0eunMJoHN9SKl3FwVzObNJ1P3B0h-NCVho6CNCNWhCDdHmgi"
	  }
	]
  }`
	malformedSigningKey = "bla"
)

func prepare(t *testing.T) (certs.CertStore, *ecdsa.PrivateKey) {
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	// creating an initial signing certificate
	store := certs.NewRedisStore(&certs.Config{
		RedisClient: c,
	})
	_, err := store.LatestPrivate(context.Background())
	require.NoError(t, err)

	key, err := store.LatestPrivate(context.Background())
	require.NoError(t, err)

	return store, key
}

func Test_opa_authorize_with_permissions(t *testing.T) {
	var (
		expired = -time.Hour
		c, key  = prepare(t)
	)

	type args struct {
		token      string
		methodName string
		req        any
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "unknown service is not allowed",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "", Methods: []string{"/api.v1.UnknownService/Get"}}}, nil, nil, key),
				methodName: "/api.v1.UnknownService/Get",
				req:        nil,
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:method denied or unknown:/api.v1.UnknownService/Get")),
		},
		{
			name: "cluster get not allowed, no token",
			args: args{
				token:      "",
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:token is not valid")),
		},
		{
			name: "cluster get not allowed, token secret malformed",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "", Methods: []string{"/api.v1.IPService/Get"}}}, nil, nil, &malformedSigningKey),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:token is not valid")),
		},
		{
			name: "cluster get not allowed, token secret malicious",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "", Methods: []string{"/api.v1.IPService/Get"}}}, nil, nil, &maliciousSigningKey),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:token is not valid")),
		},
		{
			name: "cluster get not allowed, token already expired",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "", Methods: []string{"/api.v1.IPService/Get"}}}, nil, &expired, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:token is not valid")),
		},
		{
			name: "cluster get allowed",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "project-a", Methods: []string{"/api.v1.IPService/Get"}}}, nil, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
		},
		{
			name: "method not known",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "project-a", Methods: []string{"/api.v1.IPService/Get"}}}, nil, nil, key),
				methodName: "/api.v1.IPService/Gest",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:method denied or unknown:/api.v1.IPService/Gest")),
		},
		{
			name: "cluster get not allowed",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "project-a", Methods: []string{"/api.v1.IPService/List"}}}, nil, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.IPService/Get")),
		},
		{
			name: "cluster list allowed",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "project-a", Methods: []string{"/api.v1.IPService/List"}}}, nil, nil, key),
				methodName: "/api.v1.IPService/List",
				req:        v1.IPServiceListRequest{Project: "project-a"},
			},
		},
		{
			name: "cluster create allowed",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "project-a", Methods: []string{"/api.v1.IPService/Allocate"}}}, nil, nil, key),
				methodName: "/api.v1.IPService/Allocate",
				req:        v1.IPServiceAllocateRequest{Project: "project-a"},
			},
		},
		{
			name: "cluster create not allowed, wrong project",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "project-a", Methods: []string{"/api.v1.IPService/Allocate"}}}, nil, nil, key),
				methodName: "/api.v1.IPService/Allocate",
				req:        v1.IPServiceAllocateRequest{Project: "project-b"},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.IPService/Allocate")),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			o, err := New(Config{
				Log:            slog.Default(),
				CertStore:      c,
				AllowedIssuers: []string{"mc"},
			})
			require.NoError(t, err)

			jwtTokenFunc := func(_ string) string {
				return "Bearer " + tt.args.token
			}

			_, err = o.authorize(context.Background(), tt.args.methodName, jwtTokenFunc, tt.args.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf(err.Error())
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}
func Test_opa_authorize_adminapi(t *testing.T) {
	var (
		c, key = prepare(t)
	)

	type args struct {
		token      string
		methodName string
		req        any
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "admin api tenantlist is not allowed with MethodPermissions",
			args: args{
				token:      mustToken([]*v1.MethodPermission{{Subject: "project-a", Methods: []string{"/admin.v1.TenantService/List"}}}, nil, nil, key),
				methodName: "/admin.v1.TenantService/List",
				req:        adminv1.TenantServiceListRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/admin.v1.TenantService/List")),
		},
		{
			name: "admin api tenantlist is allowed",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Role: "admin", Subject: "*"}}, nil, key),
				methodName: "/admin.v1.TenantService/List",
				req:        adminv1.TenantServiceListRequest{},
			},
			wantErr: nil,
		},
		// FIXME more admin roles defined in proto must be checked/implemented
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			o, err := New(Config{
				Log:            slog.Default(),
				CertStore:      c,
				AllowedIssuers: []string{"mc"},
			})
			require.NoError(t, err)

			jwtTokenFunc := func(_ string) string {
				return "Bearer " + tt.args.token
			}

			_, err = o.authorize(context.Background(), tt.args.methodName, jwtTokenFunc, tt.args.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}

func Test_opa_authorize_ip_services(t *testing.T) {
	var (
		c, key = prepare(t)
	)

	type args struct {
		token      string
		methodName string
		req        any
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "ip get allowed for owner",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-a", Role: v1.OWNER}}, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
		},
		{
			name: "ip get allowed for viewer",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-a", Role: v1.VIEWER}}, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
		},
		{
			name: "ip get not allowed wrong project in role",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-b", Role: v1.VIEWER}}, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.IPService/Get")),
		},
		{
			name: "ip allocate allowed for owner",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-b", Role: v1.OWNER}}, nil, key),
				methodName: "/api.v1.IPService/Allocate",
				req:        v1.IPServiceAllocateRequest{Project: "project-b"},
			},
		},
		{
			name: "ip allocate not allowed for viewer",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-b", Role: v1.VIEWER}}, nil, key),
				methodName: "/api.v1.IPService/Allocate",
				req:        v1.IPServiceAllocateRequest{Project: "project-b"},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.IPService/Allocate")),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			o, err := New(Config{
				Log:            slog.Default(),
				CertStore:      c,
				AllowedIssuers: []string{"mc"},
			})
			require.NoError(t, err)

			jwtTokenFunc := func(_ string) string {
				return "Bearer " + tt.args.token
			}

			_, err = o.authorize(context.Background(), tt.args.methodName, jwtTokenFunc, tt.args.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}

func Test_opa_authorize_volume_services(t *testing.T) {
	var (
		c, key = prepare(t)
	)

	type args struct {
		token      string
		methodName string
		req        any
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "ip get allowed for owner",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-a", Role: v1.OWNER}}, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
		},
		{
			name: "ip get allowed for viewer",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-a", Role: v1.VIEWER}}, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
		},
		{
			name: "ip get not allowed wrong project in role",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-b", Role: v1.VIEWER}}, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.IPService/Get")),
		},
		{
			name: "ip delete allowed for owner",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-b", Role: v1.OWNER}}, nil, key),
				methodName: "/api.v1.IPService/Delete",
				req:        v1.IPServiceDeleteRequest{Project: "project-b"},
			},
		},
		{
			name: "ip allocate not allowed for viewer",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-b", Role: v1.VIEWER}}, nil, key),
				methodName: "/api.v1.IPService/Allocate",
				req:        v1.IPServiceDeleteRequest{Project: "project-b"},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:method denied or unknown:/api.v1.IPService/Allocate")),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			o, err := New(Config{
				Log:            slog.Default(),
				CertStore:      c,
				AllowedIssuers: []string{"mc"},
			})
			require.NoError(t, err)
			jwtTokenFunc := func(_ string) string {
				return "Bearer " + tt.args.token
			}

			_, err = o.authorize(context.Background(), tt.args.methodName, jwtTokenFunc, tt.args.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}

func Test_opa_authorize_allowed_services(t *testing.T) {
	var (
		c, key = prepare(t)
	)

	type args struct {
		authheader string
		methodName string
		req        any
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "version service allowed",
			args: args{
				authheader: "",
				methodName: "/api.v1.VersionService/Get",
				req:        v1.VersionServiceGetRequest{},
			},
		},
		{
			name: "health service allowed",
			args: args{
				authheader: "",
				methodName: "/api.v1.HealthService/Get",
				req:        v1.HealthServiceGetRequest{},
			},
		},
		{
			name: "token service has visibility self",
			args: args{
				authheader: "Bearer " + mustToken(nil, []*v1.TokenRole{{Subject: "john.doe@github", Role: v1.OWNER}}, nil, key),
				methodName: "/api.v1.TokenService/Create",
				req:        v1.TokenServiceCreateRequest{},
			},
		},
		{
			name: "project list service has visibility self",
			args: args{
				authheader: "Bearer " + mustToken([]*v1.MethodPermission{{Subject: "a-project", Methods: []string{"/api.v1.IPService/List"}}}, nil, nil, key),
				methodName: "/api.v1.ProjectService/List",
				req:        v1.ProjectServiceListRequest{},
			},
		},
		{
			name: "project list service has visibility self but token has not permissions",
			args: args{
				authheader: "Bearer " + mustToken(nil, nil, nil, key),
				methodName: "/api.v1.ProjectService/List",
				req:        v1.ProjectServiceListRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.ProjectService/List")),
		},
		{
			name: "project get service has not visibility self",
			args: args{
				authheader: "Bearer " + mustToken([]*v1.MethodPermission{{Subject: "a-project", Methods: []string{"/api.v1.IPService/List"}}}, nil, nil, key),
				methodName: "/api.v1.ProjectService/Get",
				req:        v1.ProjectServiceListRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.ProjectService/Get")),
		},
		{
			name: "token service malformed token",
			args: args{
				authheader: "Bearer " + mustToken(nil, []*v1.TokenRole{{Subject: "john.doe@github", Role: v1.OWNER}}, nil, key) + "foo",
				methodName: "/api.v1.TokenService/List",
				req:        v1.TokenServiceListRequest{},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.TokenService/List")),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			o, err := New(Config{
				Log:            slog.Default(),
				CertStore:      c,
				AllowedIssuers: []string{"mc"},
			})

			require.NoError(t, err)
			jwtTokenFunc := func(_ string) string {
				// Intentionally left bearer token aside
				return tt.args.authheader
			}

			_, err = o.authorize(context.Background(), tt.args.methodName, jwtTokenFunc, tt.args.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}

func Test_opa_authorize_returns_claims(t *testing.T) {
	var (
		c, key = prepare(t)
	)

	type args struct {
		token      string
		methodName string
		req        any
	}
	tests := []struct {
		name        string
		args        args
		wantedRoles token.TokenRoles
		wantErr     error
	}{
		{
			name: "ip get service allowed, claims are returned",
			args: args{
				token:      mustToken(nil, []*v1.TokenRole{{Subject: "project-a", Role: v1.OWNER}}, nil, key),
				methodName: "/api.v1.IPService/Get",
				req:        v1.IPServiceGetRequest{Project: "project-a"},
			},
			wantedRoles: token.TokenRoles{
				"project-a": "owner",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			o, err := New(Config{
				Log:            slog.Default(),
				CertStore:      c,
				AllowedIssuers: []string{"mc"},
			})

			require.NoError(t, err)
			jwtTokenFunc := func(_ string) string {
				return "Bearer " + tt.args.token
			}

			claims, err := o.authorize(context.Background(), tt.args.methodName, jwtTokenFunc, tt.args.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
			assert.NotNil(t, claims)
			assert.Equal(t, tt.wantedRoles, claims.Roles)
		})
	}
}

func mustToken(MethodPermissions []*v1.MethodPermission, roles []*v1.TokenRole, expires *time.Duration, key crypto.PrivateKey) string {
	exp := time.Hour
	if expires != nil {
		exp = *expires
	}

	t, _, _ := token.NewJWT(v1.TokenType_TOKEN_TYPE_CONSOLE, "john.doe@github", "mc", roles, MethodPermissions, exp, key)

	return t
}
