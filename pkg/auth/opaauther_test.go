package auth

import (
	"context"
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
	adminv1 "github.com/metal-stack/api/go/admin/v1"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/pkg/testcommon"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
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
		certStore, key = prepare(t)
		defaultIssuer  = "https://api-server"
	)

	tests := []struct {
		name            string
		subject         string
		method          string
		permissions     []*apiv1.MethodPermission
		projectRoles    map[string]apiv1.ProjectRole
		tenantRoles     map[string]apiv1.TenantRole
		adminRole       *apiv1.AdminRole
		userJwtMutateFn func(t *testing.T, jwt string) string
		expiration      *time.Duration
		req             any
		wantErr         error
	}{
		{
			name:    "unknown service is not allowed",
			subject: "john.doe@github",
			method:  "/api.v1.UnknownService/Get",
			req:     nil,
			permissions: []*apiv1.MethodPermission{
				{
					Subject: "john.doe@github",
					Methods: []string{"/api.v1.UnknownService/Get"},
				},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:method denied or unknown:/api.v1.UnknownService/Get")),
		},
		// FIXME: these tests did not work before because error was suppressed, fix them :(
		// {
		// 	name:    "cluster get not allowed, token secret malicious",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.ClusterService/Get",
		// 	req:     v1.ClusterServiceGetRequest{},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "",
		// 			Methods: []string{"/api.v1.ClusterService/Get"},
		// 		},
		// 	},
		// 	userJwtMutateFn: func(t *testing.T, _ string) string {
		// 		jwt, _, err := token.NewJWT(v1.TokenType_TOKEN_TYPE_CONSOLE, "john.doe@github", defaultIssuer, 1*time.Hour, maliciousSigningKey)
		// 		require.NoError(t, err)
		// 		return jwt
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:token is not valid")),
		// },
		// {
		// 	name: "cluster get not allowed, token secret malicious",
		// 	args: args{
		// 		token:      mustToken([]*v1.MethodPermission{{Subject: "", Methods: []string{"/api.v1.ClusterService/Get"}}}, nil, nil, &maliciousSigningKey),
		// 		methodName: "/api.v1.ClusterService/Get",
		// 		req:        v1.ClusterServiceGetRequest{},
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:token is not valid")),
		// },

		{
			name:    "admin api tenantlist is not allowed with MethodPermissions",
			subject: "john.doe@github",
			method:  "/admin.v1.TenantService/List",
			req:     adminv1.TenantServiceListRequest{},
			permissions: []*apiv1.MethodPermission{
				{
					Subject: "john.doe@github",
					Methods: []string{"/admin.v1.TenantService/List"},
				},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/admin.v1.TenantService/List")),
		},
		{
			name:        "admin api tenantlist is allowed",
			subject:     "john.doe@github",
			method:      "/admin.v1.TenantService/List",
			req:         adminv1.TenantServiceListRequest{},
			permissions: []*apiv1.MethodPermission{},
			adminRole:   pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR),
		},
		{
			name:        "admin editor accessed api/v1 methods tenant invite is allowed",
			subject:     "john.doe@github",
			method:      "/api.v1.TenantService/Invite",
			req:         apiv1.TenantServiceInvitesListRequest{},
			permissions: []*apiv1.MethodPermission{},
			adminRole:   pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR),
		},
		{
			name:        "admin viewer accessed api/v1 methods tenant invite is allowed",
			subject:     "john.doe@github",
			method:      "/api.v1.TenantService/Invite",
			req:         apiv1.TenantServiceInvitesListRequest{},
			permissions: []*apiv1.MethodPermission{},
			adminRole:   pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_VIEWER),
			wantErr:     connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.TenantService/Invite")),
		},
		{
			name:        "admin editor can access api/v1 self methods",
			subject:     "john.doe@github",
			method:      "/api.v1.TenantService/InviteGet",
			req:         apiv1.TenantServiceInviteGetRequest{},
			permissions: []*apiv1.MethodPermission{},
			adminRole:   pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR),
		},

		{
			name:    "version service allowed without token because it is public visibility",
			subject: "",
			method:  "/api.v1.VersionService/Get",
			req:     apiv1.VersionServiceGetRequest{},
			userJwtMutateFn: func(_ *testing.T, _ string) string {
				return ""
			},
		},
		{
			name:    "health service allowed without token because it is public visibility",
			subject: "",
			method:  "/api.v1.HealthService/Get",
			req:     apiv1.HealthServiceGetRequest{},
			userJwtMutateFn: func(_ *testing.T, _ string) string {
				return ""
			},
		},
		{
			name:    "token service has visibility self",
			subject: "john.doe@github",
			method:  "/api.v1.TokenService/Create",
			req:     apiv1.TokenServiceCreateRequest{},
			tenantRoles: map[string]apiv1.TenantRole{
				"john.doe@github": apiv1.TenantRole_TENANT_ROLE_OWNER,
			},
		},
		{
			name:    "token service malformed token",
			subject: "john.doe@github",
			method:  "/api.v1.TokenService/Create",
			req:     apiv1.TokenServiceCreateRequest{},
			userJwtMutateFn: func(_ *testing.T, jwt string) string {
				return jwt + "foo"
			},
			tenantRoles: map[string]apiv1.TenantRole{
				"john.doe@github": apiv1.TenantRole_TENANT_ROLE_OWNER,
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.TokenService/Create")),
		},
		{
			name:    "project list service has visibility self",
			subject: "john.doe@github",
			method:  "/api.v1.ProjectService/List",
			req:     apiv1.ProjectServiceListRequest{},
			permissions: []*apiv1.MethodPermission{
				{
					Subject: "a-project",
					Methods: []string{"/api.v1.ClusterService/List"},
				},
			},
			// TODO: I don't really understand why any permissions are necessary?
		},
		{
			name:    "project list service has visibility self but token has not permissions",
			subject: "john.doe@github",
			method:  "/api.v1.ProjectService/List",
			req:     apiv1.ProjectServiceListRequest{},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.ProjectService/List")),
		},
		{
			name:    "project get service has not visibility self",
			subject: "john.doe@github",
			method:  "/api.v1.ProjectService/Get",
			req:     apiv1.ProjectServiceGetRequest{Project: "a-project"},
			permissions: []*apiv1.MethodPermission{
				{
					Subject: "a-project",
					Methods: []string{"/api.v1.ClusterService/List"},
				},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied to:/api.v1.ProjectService/Get")),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			s := miniredis.RunT(t)
			defer s.Close()

			ctx := context.Background()
			tokenStore := token.NewRedisStore(redis.NewClient(&redis.Options{Addr: s.Addr()}))

			exp := time.Hour
			if tt.expiration != nil {
				exp = *tt.expiration
			}

			jwt, tok, err := token.NewJWT(apiv1.TokenType_TOKEN_TYPE_CONSOLE, tt.subject, defaultIssuer, exp, key)
			require.NoError(t, err)

			if tt.userJwtMutateFn != nil {
				jwt = tt.userJwtMutateFn(t, jwt)
			}

			tok.Permissions = tt.permissions
			tok.ProjectRoles = tt.projectRoles
			tok.TenantRoles = tt.tenantRoles
			tok.AdminRole = tt.adminRole

			err = tokenStore.Set(ctx, tok)
			require.NoError(t, err)

			o, err := New(Config{
				Log:            slog.Default(),
				CertStore:      certStore,
				CertCacheTime:  pointer.Pointer(0 * time.Second),
				TokenStore:     tokenStore,
				AllowedIssuers: []string{defaultIssuer},
			})
			require.NoError(t, err)

			jwtTokenFunc := func(_ string) string {
				return "Bearer " + jwt
			}

			_, err = o.authorize(ctx, tt.method, jwtTokenFunc, tt.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf(err.Error())
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}
