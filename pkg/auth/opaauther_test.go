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
	putil "github.com/metal-stack/api-server/pkg/project"
	"github.com/metal-stack/api-server/pkg/token"
	adminv1 "github.com/metal-stack/api/go/admin/v1"
	v1 "github.com/metal-stack/api/go/api/v1"
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
		name               string
		subject            string
		method             string
		permissions        []*v1.MethodPermission
		projectRoles       map[string]v1.ProjectRole
		tenantRoles        map[string]v1.TenantRole
		adminRole          *v1.AdminRole
		userJwtMutateFn    func(t *testing.T, jwt string) string
		expiration         *time.Duration
		req                any
		projectsAndTenants *putil.ProjectsAndTenants
		tokenType          v1.TokenType
		wantErr            error
	}{
		{
			name:    "unknown service is not allowed",
			subject: "john.doe@github",
			method:  "/api.v1.UnknownService/Get",
			req:     nil,
			permissions: []*v1.MethodPermission{
				{
					Subject: "john.doe@github",
					Methods: []string{"/api.v1.UnknownService/Get"},
				},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("method denied or unknown: /api.v1.UnknownService/Get")),
		},
		// {
		// 	name:    "cluster get not allowed, no token",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/Get",
		// 	req:     v1.ClusterServiceGetRequest{},
		// 	userJwtMutateFn: func(t *testing.T, jwt string) string {
		// 		return ""
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.IPService/Get")),
		// },
		// FIXME: these tests did not work before because error was suppressed, fix them :(
		// {
		// 	name:    "cluster get not allowed, token secret malicious",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/Get",
		// 	req:     v1.ClusterServiceGetRequest{},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "",
		// 			Methods: []string{"/api.v1.IPService/Get"},
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
		// 		token:      mustToken([]*v1.MethodPermission{{Subject: "", Methods: []string{"/api.v1.IPService/Get"}}}, nil, nil, &maliciousSigningKey),
		// 		methodName: "/api.v1.IPService/Get",
		// 		req:        v1.ClusterServiceGetRequest{},
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("access denied:token is not valid")),
		// },
		// {
		// 	name:       "cluster get not allowed, token already expired",
		// 	subject:    "john.doe@github",
		// 	method:     "/api.v1.IPService/Get",
		// 	req:        v1.ClusterServiceGetRequest{},
		// 	expiration: &expired,
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "john.doe@github",
		// 			Methods: []string{"/api.v1.IPService/Get"},
		// 		},
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token has expired")),
		// },
		// {
		// 	name:    "cluster get allowed",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/Get",
		// 	req:     v1.ClusterServiceGetRequest{Project: "john.doe@github"},
		// 	projectsAndTenants: &putil.ProjectsAndTenants{
		// 		ProjectRoles: map[string]v1.ProjectRole{
		// 			"john.doe@github": v1.ProjectRole_PROJECT_ROLE_EDITOR,
		// 		},
		// 	},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "john.doe@github",
		// 			Methods: []string{"/api.v1.IPService/Get"},
		// 		},
		// 	},
		// },
		// {
		// 	name:    "method not known",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/Gest",
		// 	req:     v1.ClusterServiceGetRequest{Project: "john.doe@github"},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "john.doe@github",
		// 			Methods: []string{"/api.v1.IPService/Get"},
		// 		},
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("method denied or unknown: /api.v1.IPService/Gest")),
		// },
		// {
		// 	name:    "cluster get not allowed",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/Get",
		// 	req:     v1.ClusterServiceGetRequest{Project: "john.doe@github"},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "john.doe@github",
		// 			Methods: []string{"/api.v1.IPService/List"},
		// 		},
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.IPService/Get")),
		// },
		// {
		// 	name:    "cluster list allowed",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/List",
		// 	req:     v1.ClusterServiceGetRequest{Project: "john.doe@github"},
		// 	projectsAndTenants: &putil.ProjectsAndTenants{
		// 		ProjectRoles: map[string]v1.ProjectRole{
		// 			"john.doe@github": v1.ProjectRole_PROJECT_ROLE_EDITOR,
		// 		},
		// 	},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "john.doe@github",
		// 			Methods: []string{"/api.v1.IPService/List"},
		// 		},
		// 	},
		// },
		// {
		// 	name:    "cluster create allowed",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/Create",
		// 	req:     v1.ClusterServiceGetRequest{Project: "john.doe@github"},
		// 	projectsAndTenants: &putil.ProjectsAndTenants{
		// 		ProjectRoles: map[string]v1.ProjectRole{
		// 			"john.doe@github": v1.ProjectRole_PROJECT_ROLE_EDITOR,
		// 		},
		// 	},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "john.doe@github",
		// 			Methods: []string{"/api.v1.IPService/List", "/api.v1.IPService/Create"},
		// 		},
		// 	},
		// },
		// {
		// 	name:    "cluster create not allowed, wrong project",
		// 	subject: "john.doe@github",
		// 	method:  "/api.v1.IPService/Create",
		// 	req:     v1.ClusterServiceGetRequest{Project: "john.doe@github"},
		// 	permissions: []*v1.MethodPermission{
		// 		{
		// 			Subject: "project-a",
		// 			Methods: []string{"/api.v1.IPService/List", "/api.v1.IPService/Create"},
		// 		},
		// 	},
		// 	wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.IPService/Create")),
		// },
		{
			name:    "admin api tenantlist is not allowed with MethodPermissions",
			subject: "john.doe@github",
			method:  "/admin.v1.TenantService/List",
			req:     adminv1.TenantServiceListRequest{},
			permissions: []*v1.MethodPermission{
				{
					Subject: "john.doe@github",
					Methods: []string{"/admin.v1.TenantService/List"},
				},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /admin.v1.TenantService/List")),
		},
		{
			name:        "admin api tenantlist is allowed",
			subject:     "john.doe@github",
			method:      "/admin.v1.TenantService/List",
			req:         adminv1.TenantServiceListRequest{},
			permissions: []*v1.MethodPermission{},
			adminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_EDITOR),
		},
		{
			name:        "admin api tenantlist is not allowed because he is not in the list of allowed admin subjects",
			subject:     "hein.bloed@github",
			method:      "/admin.v1.TenantService/List",
			req:         adminv1.TenantServiceListRequest{},
			permissions: []*v1.MethodPermission{},
			adminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_EDITOR),
			wantErr:     connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /admin.v1.TenantService/List")),
		},
		{
			name:        "admin editor accessed api/v1 methods tenant invite is allowed",
			subject:     "john.doe@github",
			method:      "/api.v1.TenantService/Invite",
			req:         v1.TenantServiceInvitesListRequest{},
			permissions: []*v1.MethodPermission{},
			adminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_EDITOR),
		},
		{
			name:        "admin viewer accessed api/v1 methods tenant invite is allowed",
			subject:     "john.doe@github",
			method:      "/api.v1.TenantService/Invite",
			req:         v1.TenantServiceInvitesListRequest{},
			permissions: []*v1.MethodPermission{},
			adminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_VIEWER),
			wantErr:     connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.TenantService/Invite")),
		},
		{
			name:        "admin editor can access api/v1 self methods",
			subject:     "john.doe@github",
			method:      "/api.v1.TenantService/InviteGet",
			req:         v1.TenantServiceInviteGetRequest{},
			permissions: []*v1.MethodPermission{},
			adminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_EDITOR),
		},
		// FIXME more admin roles defined in proto must be checked/implemented
		{
			name:        "ip get allowed for owner",
			subject:     "john.doe@github",
			method:      "/api.v1.IPService/Get",
			req:         v1.IPServiceGetRequest{Project: "project-a"},
			permissions: []*v1.MethodPermission{},
			projectsAndTenants: &putil.ProjectsAndTenants{
				ProjectRoles: map[string]v1.ProjectRole{
					"project-a": v1.ProjectRole_PROJECT_ROLE_OWNER,
				},
			},
			projectRoles: map[string]v1.ProjectRole{
				"project-a": v1.ProjectRole_PROJECT_ROLE_OWNER,
			},
		},
		{
			name:        "ip get allowed for viewer",
			subject:     "john.doe@github",
			method:      "/api.v1.IPService/Get",
			req:         v1.IPServiceGetRequest{Project: "project-a"},
			permissions: []*v1.MethodPermission{},
			projectsAndTenants: &putil.ProjectsAndTenants{
				ProjectRoles: map[string]v1.ProjectRole{
					"project-a": v1.ProjectRole_PROJECT_ROLE_VIEWER,
				},
			},
			projectRoles: map[string]v1.ProjectRole{
				"project-a": v1.ProjectRole_PROJECT_ROLE_VIEWER,
			},
		},
		{
			name:        "ip get not allowed, wrong project requested",
			subject:     "john.doe@github",
			method:      "/api.v1.IPService/Get",
			req:         v1.IPServiceGetRequest{Project: "project-b"},
			permissions: []*v1.MethodPermission{},
			projectRoles: map[string]v1.ProjectRole{
				"project-a": v1.ProjectRole_PROJECT_ROLE_VIEWER,
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.IPService/Get")),
		},
		{
			name:        "ip allocate allowed for owner",
			subject:     "john.doe@github",
			method:      "/api.v1.IPService/Allocate",
			req:         v1.IPServiceAllocateRequest{Project: "project-a"},
			permissions: []*v1.MethodPermission{},
			projectsAndTenants: &putil.ProjectsAndTenants{
				ProjectRoles: map[string]v1.ProjectRole{
					"project-a": v1.ProjectRole_PROJECT_ROLE_OWNER,
				},
			},
			projectRoles: map[string]v1.ProjectRole{
				"project-a": v1.ProjectRole_PROJECT_ROLE_OWNER,
			},
		},
		{
			name:        "ip allocate not allowed for viewer",
			subject:     "john.doe@github",
			method:      "/api.v1.IPService/Allocate",
			req:         v1.IPServiceAllocateRequest{Project: "project-a"},
			permissions: []*v1.MethodPermission{},
			projectRoles: map[string]v1.ProjectRole{
				"project-a": v1.ProjectRole_PROJECT_ROLE_VIEWER,
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.IPService/Allocate")),
		},
		{
			name:    "version service allowed without token because it is public visibility",
			subject: "",
			method:  "/api.v1.VersionService/Get",
			req:     v1.VersionServiceGetRequest{},
			userJwtMutateFn: func(_ *testing.T, _ string) string {
				return ""
			},
		},
		{
			name:    "health service allowed without token because it is public visibility",
			subject: "",
			method:  "/api.v1.HealthService/Get",
			req:     v1.HealthServiceGetRequest{},
			userJwtMutateFn: func(_ *testing.T, _ string) string {
				return ""
			},
		},
		{
			name:    "token service has visibility self",
			subject: "john.doe@github",
			method:  "/api.v1.TokenService/Create",
			req:     v1.TokenServiceCreateRequest{},
			projectsAndTenants: &putil.ProjectsAndTenants{
				TenantRoles: map[string]v1.TenantRole{
					"john.doe@github": v1.TenantRole_TENANT_ROLE_OWNER,
				},
			},
			tenantRoles: map[string]v1.TenantRole{
				"john.doe@github": v1.TenantRole_TENANT_ROLE_OWNER,
			},
		},
		{
			name:    "token service malformed token",
			subject: "john.doe@github",
			method:  "/api.v1.TokenService/Create",
			req:     v1.TokenServiceCreateRequest{},
			userJwtMutateFn: func(_ *testing.T, jwt string) string {
				return jwt + "foo"
			},
			tenantRoles: map[string]v1.TenantRole{
				"john.doe@github": v1.TenantRole_TENANT_ROLE_OWNER,
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token")),
		},
		{
			name:    "project list service has visibility self",
			subject: "john.doe@github",
			method:  "/api.v1.ProjectService/List",
			req:     v1.ProjectServiceListRequest{},
			projectsAndTenants: &putil.ProjectsAndTenants{
				TenantRoles: map[string]v1.TenantRole{
					"john.doe@github": v1.TenantRole_TENANT_ROLE_OWNER,
				},
			},
			permissions: []*v1.MethodPermission{
				{
					Subject: "a-project",
					Methods: []string{"/api.v1.IPService/List"},
				},
			},
			// TODO: I don't really understand why any permissions are necessary?
		},
		{
			name:    "project list service has visibility self but token has not permissions",
			subject: "john.doe@github",
			method:  "/api.v1.ProjectService/List",
			req:     v1.ProjectServiceListRequest{},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.ProjectService/List")),
		},
		{
			name:    "project get service has not visibility self",
			subject: "john.doe@github",
			method:  "/api.v1.ProjectService/Get",
			req:     v1.ProjectServiceGetRequest{Project: "a-project"},
			permissions: []*v1.MethodPermission{
				{
					Subject: "a-project",
					Methods: []string{"/api.v1.IPService/List"},
				},
			},
			wantErr: connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not allowed to call: /api.v1.ProjectService/Get")),
		},
		{
			name:      "access project with console token",
			subject:   "john.doe@github",
			method:    "/api.v1.ProjectService/Get",
			req:       v1.ProjectServiceGetRequest{Project: "project-a"},
			tokenType: v1.TokenType_TOKEN_TYPE_CONSOLE,
			projectsAndTenants: &putil.ProjectsAndTenants{
				ProjectRoles: map[string]v1.ProjectRole{
					"project-a": v1.ProjectRole_PROJECT_ROLE_OWNER,
				},
			},
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

			tokenType := v1.TokenType_TOKEN_TYPE_API
			if tt.tokenType != v1.TokenType_TOKEN_TYPE_UNSPECIFIED {
				tokenType = tt.tokenType
			}

			jwt, tok, err := token.NewJWT(tokenType, tt.subject, defaultIssuer, exp, key)
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
				AdminSubjects:  []string{"john.doe@github"},
			})
			require.NoError(t, err)

			o.projectsAndTenantsGetter = func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error) {
				if tt.projectsAndTenants == nil {
					return &putil.ProjectsAndTenants{}, nil
				}
				return tt.projectsAndTenants, nil
			}

			jwtTokenFunc := func(_ string) string {
				return "Bearer " + jwt
			}

			_, err = o.decide(ctx, tt.method, jwtTokenFunc, tt.req)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Error(err.Error())
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}
