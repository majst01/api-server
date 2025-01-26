package token

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/metal-stack/api-server/pkg/certs"
	putil "github.com/metal-stack/api-server/pkg/project"
	"github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/permissions"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
)

func Test_tokenService_CreateConsoleTokenWithoutPermissionCheck(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	tokenStore := token.NewRedisStore(c)
	certStore := certs.NewRedisStore(&certs.Config{
		RedisClient: c,
	})

	service := New(Config{
		Log:          slog.Default(),
		TokenStore:   tokenStore,
		CertStore:    certStore,
		MasterClient: nil,
		Issuer:       "http://test",
	})

	got, err := service.CreateConsoleTokenWithoutPermissionCheck(ctx, "test", pointer.Pointer(1*time.Minute))
	require.NoError(t, err)
	// verifying response

	require.NotNil(t, got)
	require.NotNil(t, got.Msg)
	require.NotNil(t, got.Msg.GetToken())

	assert.NotEmpty(t, got.Msg.GetSecret())
	assert.True(t, strings.HasPrefix(got.Msg.GetSecret(), "ey"), "not a valid jwt token") // jwt always starts with "ey" because it's b64 encoded JSON
	claims, err := token.ParseJWTToken(got.Msg.GetSecret())
	require.NoError(t, err, "token claims not parsable")
	require.NotNil(t, claims)

	assert.NotEmpty(t, got.Msg.GetToken().GetUuid())
	assert.Equal(t, "test", got.Msg.GetToken().GetUserId())

	// verifying keydb entry
	err = tokenStore.Set(ctx, got.Msg.GetToken())
	require.NoError(t, err)

	// listing tokens

	tokenList, err := service.List(token.ContextWithToken(ctx, got.Msg.Token), &connect.Request[v1.TokenServiceListRequest]{})
	require.NoError(t, err)

	require.NotNil(t, tokenList)
	require.NotNil(t, tokenList.Msg)

	require.Len(t, tokenList.Msg.Tokens, 1)

	// Check still present
	_, err = tokenStore.Get(ctx, got.Msg.GetToken().GetUserId(), got.Msg.GetToken().GetUuid())
	require.NoError(t, err)

	// Check unpresent after revocation
	err = tokenStore.Revoke(ctx, got.Msg.GetToken().GetUserId(), got.Msg.GetToken().GetUuid())
	require.NoError(t, err)

	_, err = tokenStore.Get(ctx, got.Msg.GetToken().GetUserId(), got.Msg.GetToken().GetUuid())
	require.Error(t, err)

	// List must now be empty
	tokenList, err = service.List(token.ContextWithToken(ctx, got.Msg.Token), &connect.Request[v1.TokenServiceListRequest]{})
	require.NoError(t, err)

	require.NotNil(t, tokenList)
	require.NotNil(t, tokenList.Msg)
	require.Empty(t, tokenList.Msg.Tokens)
}

func Test_Create(t *testing.T) {
	type state struct {
		adminSubjects []string
		projectRoles  map[string]v1.ProjectRole
		tenantRoles   map[string]v1.TenantRole
	}
	tests := []struct {
		name           string
		sessionToken   *v1.Token
		req            *v1.TokenServiceCreateRequest
		state          state
		wantErr        bool
		wantErrMessage string
		wantToken      *v1.Token
	}{
		{
			name: "can create bare token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "empty token",
			},
			state: state{
				adminSubjects: []string{},
			},
			wantToken: &v1.Token{
				UserId:      "phippy",
				Description: "empty token",
				TokenType:   v1.TokenType_TOKEN_TYPE_API,
			},
		},
		{
			name: "user and token without project access cannot create project token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "project token",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested project:"kubies" is not allowed`,
		},
		{
			name: "user and token with project access can create project token",
			sessionToken: &v1.Token{
				UserId:      "phippy",
				Permissions: []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "project token",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
			},
			wantToken: &v1.Token{
				UserId:      "phippy",
				Description: "project token",
				TokenType:   v1.TokenType_TOKEN_TYPE_API,
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},

				TenantRoles: map[string]v1.TenantRole{},
			},
		},
		{
			name: "user without but token with project access cannot create project token",
			sessionToken: &v1.Token{
				UserId:      "phippy",
				Permissions: []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "project token",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles:  map[string]v1.ProjectRole{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: outdated token: requested project:"kubies" is not allowed`,
		},
		{
			name: "project without but user with project access cannot create project token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "project token",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested project:"kubies" is not allowed`,
		},
		{
			name: "admin user and token can create new admin token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			req: &v1.TokenServiceCreateRequest{
				Description:  "admin token",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			state: state{
				adminSubjects: []string{"phippy"},
			},
			wantToken: &v1.Token{
				UserId:       "phippy",
				Description:  "admin token",
				TokenType:    v1.TokenType_TOKEN_TYPE_API,
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
		},
		{
			name: "admin token but not user cannot create new admin token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			req: &v1.TokenServiceCreateRequest{
				Description:  "admin token",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			state: state{
				adminSubjects: []string{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: outdated token: requested admin role:"ADMIN_ROLE_EDITOR" is not allowed`,
		},

		{
			name: "user and token without tenant access cannot create tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description:  "project token",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested tenant:"mascots" is not allowed`,
		},
		{
			name: "user and token with tenant access can create tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description:  "project token",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
				tenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			wantToken: &v1.Token{
				UserId:       "phippy",
				Description:  "project token",
				TokenType:    *v1.TokenType_TOKEN_TYPE_API.Enum(),
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
		},
		{
			name: "user without but token with tenant access cannot create tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description:  "project token",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles:  map[string]v1.ProjectRole{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: outdated token: requested tenant:"mascots" is not allowed`,
		},
		{
			name: "token without but user with tenant access cannot create tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description:  "project token",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles:  map[string]v1.ProjectRole{},
				tenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested tenant:"mascots" is not allowed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(token.ContextWithToken(context.Background(), tt.sessionToken))
			defer cancel()

			s := miniredis.RunT(t)
			c := redis.NewClient(&redis.Options{Addr: s.Addr()})

			tokenStore := token.NewRedisStore(c)
			certStore := certs.NewRedisStore(&certs.Config{
				RedisClient: c,
			})

			rawService := New(Config{
				Log:           slog.Default(),
				TokenStore:    tokenStore,
				CertStore:     certStore,
				MasterClient:  nil,
				Issuer:        "http://test",
				AdminSubjects: tt.state.adminSubjects,
			})

			service, ok := rawService.(*tokenService)
			if !ok {
				t.Fatalf("want new token service to be tokenService, got: %T", rawService)
			}

			service.projectsAndTenantsGetter = func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error) {
				return &putil.ProjectsAndTenants{
					ProjectRoles: tt.state.projectRoles,
					TenantRoles:  tt.state.tenantRoles,
				}, nil
			}

			response, err := service.Create(ctx, connect.NewRequest(tt.req))
			switch {
			case tt.wantErr && err != nil:
				if dff := cmp.Diff(tt.wantErrMessage, err.Error()); dff != "" {
					t.Fatal(dff)
				}
			case tt.wantErr && err == nil:
				t.Fatalf("want error %q, got response %q", tt.wantErrMessage, response)
			case err != nil:
				t.Fatalf("want response, got error %q", err)

			default:
				if response.Msg.Secret == "" {
					t.Error("response secret for token may not be empty")
				}
				require.NotNil(t, tt.wantToken, "token returned, nil expected")

				got := response.Msg.Token
				assert.Equal(t, tt.wantToken.Description, got.Description, "description")
				assert.Equal(t, tt.wantToken.UserId, got.UserId, "user id")
				assert.Equal(t, tt.wantToken.TokenType, got.TokenType, "token type")
				assert.Equal(t, tt.wantToken.AdminRole, got.AdminRole, "admin role")
				assert.Equal(t, tt.wantToken.Permissions, got.Permissions, "permissions")
				assert.Equal(t, tt.wantToken.ProjectRoles, got.ProjectRoles, "project roles")
				assert.Equal(t, tt.wantToken.TenantRoles, got.TenantRoles, "tenant roles")
			}
		})
	}
}

func Test_validateTokenCreate(t *testing.T) {
	servicePermissions := permissions.GetServicePermissions()
	inOneHour := durationpb.New(time.Hour)
	oneHundredDays := durationpb.New(100 * 24 * time.Hour)
	tests := []struct {
		name           string
		token          *v1.Token
		req            *v1.TokenServiceCreateRequest
		adminSubjects  []string
		wantErr        bool
		wantErrMessage string
	}{
		{
			name: "simple token with empty permissions and roles",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "",
						Methods: []string{""},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i don't need any permissions",
				Expires:     inOneHour,
			},
			adminSubjects: []string{},
			wantErr:       false,
		},
		// Inherited Permissions
		{
			name: "simple token with no permissions but project role",
			token: &v1.Token{
				ProjectRoles: map[string]v1.ProjectRole{
					"ae8d2493-41ec-4efd-bbb4-81085b20b6fe": v1.ProjectRole_PROJECT_ROLE_OWNER,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster for this project",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "ae8d2493-41ec-4efd-bbb4-81085b20b6fe",
						Methods: []string{
							"/api.v1.ClusterService/Get",
						},
					},
				},
				Expires: inOneHour,
			},
			adminSubjects: []string{},
			wantErr:       false,
		},
		{
			name: "simple token with no permissions but tenant role (old naming scheme)",
			token: &v1.Token{
				TenantRoles: map[string]v1.TenantRole{
					"john@github": v1.TenantRole_TENANT_ROLE_OWNER,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to update payments",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "john@github",
						Methods: []string{
							"/api.v1.PaymentService/CreateOrUpdateCustomer",
						},
					},
				},
				Expires: inOneHour,
			},
			adminSubjects: []string{},
			wantErr:       false,
		},
		// Permissions from Token
		{
			name: "simple token with one project and permission",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				Expires: inOneHour,
			},
			adminSubjects: []string{},
			wantErr:       false,
		},
		{
			name: "simple token with unknown method",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.UnknownService/Get"},
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested method:\"/api.v1.UnknownService/Get\" is not allowed",
		},
		{
			name: "simple token with one project and permission, wrong project given",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "cde",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested subject:\"cde\" access is not allowed",
		},
		{
			name: "simple token with one project and permission, wrong message given",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to list clusters",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/List"},
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested method:\"/api.v1.ClusterService/List\" is not allowed for subject:\"abc\"",
		},
		{
			name: "simple token with one project and permission, wrong messages given",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{
							"/api.v1.ClusterService/Create",
							"/api.v1.ClusterService/Get",
							"/api.v1.ClusterService/Delete",
						},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get and list clusters",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{
							"/api.v1.ClusterService/Get",
							"/api.v1.ClusterService/List",
						},
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested method:\"/api.v1.ClusterService/List\" is not allowed for subject:\"abc\"",
		},
		{
			name: "expiration too long",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "",
						Methods: []string{""},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i don't need any permissions",
				Expires:     oneHundredDays,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested expiration duration:\"2400h0m0s\" exceeds max expiration:\"2160h0m0s\"",
		},
		// Roles from Token
		{
			name: "token has no role",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]v1.TenantRole{
					"john@github": v1.TenantRole_TENANT_ROLE_OWNER,
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested tenant:\"john@github\" is not allowed",
		},
		{
			name: "token has to low role",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]v1.TenantRole{
					"company-a@github": v1.TenantRole_TENANT_ROLE_VIEWER,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]v1.TenantRole{
					"company-a@github": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested role:\"TENANT_ROLE_EDITOR\" is higher than allowed role:\"TENANT_ROLE_VIEWER\"",
		},
		{
			name: "token request has unspecified role",
			token: &v1.Token{
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]v1.TenantRole{
					"company-a@github": v1.TenantRole_TENANT_ROLE_VIEWER,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]v1.TenantRole{
					"company-a@github": v1.TenantRole_TENANT_ROLE_UNSPECIFIED,
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested tenant role:\"TENANT_ROLE_UNSPECIFIED\" is not allowed",
		},
		// AdminSubjects
		{
			name:          "requested admin role but is not allowed",
			adminSubjects: []string{},
			token: &v1.Token{
				TenantRoles: map[string]v1.TenantRole{
					"company-a@github": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				AdminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_VIEWER),
				Expires:     inOneHour,
			},
			wantErr:        true,
			wantErrMessage: "requested admin role:\"ADMIN_ROLE_VIEWER\" is not allowed",
		},
		{
			name: "requested admin role but is only viewer of admin orga",
			adminSubjects: []string{
				"company-a@github",
			},
			token: &v1.Token{
				TenantRoles: map[string]v1.TenantRole{
					"company-a@github": v1.TenantRole_TENANT_ROLE_VIEWER,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				AdminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_EDITOR),
				Expires:     inOneHour,
			},
			wantErr:        true,
			wantErrMessage: "requested admin role:\"ADMIN_ROLE_EDITOR\" is not allowed",
		},
		{
			name: "token requested admin role but is editor in admin orga",
			adminSubjects: []string{
				"company-a@github",
			},
			token: &v1.Token{
				UserId: "company-a@github",
				TenantRoles: map[string]v1.TenantRole{
					"company-a@github": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				AdminRole:   pointer.Pointer(v1.AdminRole_ADMIN_ROLE_EDITOR),
				Expires:     inOneHour,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenCreate(tt.token, tt.req, servicePermissions, tt.adminSubjects)
			if err != nil && !tt.wantErr {
				t.Errorf("validateTokenCreate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.wantErrMessage != err.Error() {
				t.Errorf("validateTokenCreate() error.Error = %s, wantErrMsg %s", err.Error(), tt.wantErrMessage)
			}
		})
	}
}

func Test_Update(t *testing.T) {
	type state struct {
		adminSubjects []string
		projectRoles  map[string]v1.ProjectRole
		tenantRoles   map[string]v1.TenantRole
	}
	tests := []struct {
		name           string
		sessionToken   *v1.Token
		tokenToUpdate  *v1.Token
		req            *v1.TokenServiceUpdateRequest
		state          state
		wantErr        bool
		wantErrMessage string
		wantToken      *v1.Token
	}{
		{
			name: "can update bare token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			tokenToUpdate: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				TokenType:    v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid:        "111",
				Description: pointer.Pointer("update!"),
			},
			state: state{
				adminSubjects: []string{},
			},
			wantToken: &v1.Token{
				Uuid:        "111",
				UserId:      "phippy",
				Description: "update!",
				TokenType:   v1.TokenType_TOKEN_TYPE_API,
			},
		},
		{
			name: "user and token without project access cannot update project token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			tokenToUpdate: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid: "111",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested project:"kubies" is not allowed`,
		},
		{
			name: "user and token with project access can update project token",
			sessionToken: &v1.Token{
				UserId:      "phippy",
				Permissions: []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			tokenToUpdate: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				TokenType:    v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid: "111",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
			},
			wantToken: &v1.Token{
				Uuid:      "111",
				UserId:    "phippy",
				TokenType: v1.TokenType_TOKEN_TYPE_API,
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
		},
		{
			name: "user without but token with project access cannot update project token",
			sessionToken: &v1.Token{
				UserId:      "phippy",
				Permissions: []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			tokenToUpdate: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid: "111",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles:  map[string]v1.ProjectRole{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: outdated token: requested project:"kubies" is not allowed`,
		},
		{
			name: "project without but user with project access cannot create project token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			tokenToUpdate: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid: "111",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested project:"kubies" is not allowed`,
		},
		{
			name: "admin user and token can update admin token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			tokenToUpdate: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_VIEWER.Enum(),
				TokenType:    v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid:         "111",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			state: state{
				adminSubjects: []string{"phippy"},
			},
			wantToken: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				TokenType:    v1.TokenType_TOKEN_TYPE_API,
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
		},
		{
			name: "admin token but user cannot update admin token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			tokenToUpdate: &v1.Token{
				Uuid:      "111",
				UserId:    "phippy",
				TokenType: v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
				AdminRole:    v1.AdminRole_ADMIN_ROLE_EDITOR.Enum(),
			},
			state: state{
				adminSubjects: []string{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: outdated token: requested admin role:"ADMIN_ROLE_EDITOR" is not allowed`,
		},
		{
			name: "user and token without tenant access cannot update tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			tokenToUpdate: &v1.Token{
				Uuid:      "111",
				UserId:    "phippy",
				TokenType: v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid:         "111",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested tenant:"mascots" is not allowed`,
		},
		{
			name: "user and token with tenant access can update tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			tokenToUpdate: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				TokenType:    v1.TokenType_TOKEN_TYPE_API,
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles:  map[string]v1.TenantRole{},
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid:         "111",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
				tenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			wantToken: &v1.Token{
				Uuid:         "111",
				UserId:       "phippy",
				TokenType:    *v1.TokenType_TOKEN_TYPE_API.Enum(),
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
		},
		{
			name: "user without but token with tenant access cannot update tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			tokenToUpdate: &v1.Token{
				Uuid:      "111",
				UserId:    "phippy",
				TokenType: v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid:         "111",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles:  map[string]v1.ProjectRole{},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: outdated token: requested tenant:"mascots" is not allowed`,
		},
		{
			name: "token without but user with tenant access cannot update tenant token",
			sessionToken: &v1.Token{
				UserId:       "phippy",
				Permissions:  []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{},
			},
			tokenToUpdate: &v1.Token{
				Uuid:      "111",
				UserId:    "phippy",
				TokenType: v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid:         "111",
				ProjectRoles: map[string]v1.ProjectRole{},
				TenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles:  map[string]v1.ProjectRole{},
				tenantRoles: map[string]v1.TenantRole{
					"mascots": v1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			wantErr:        true,
			wantErrMessage: `permission_denied: requested tenant:"mascots" is not allowed`,
		},
		{
			name: "token does not exist in database",
			sessionToken: &v1.Token{
				UserId:      "phippy",
				Permissions: []*v1.MethodPermission{},
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
			},
			tokenToUpdate: &v1.Token{
				Uuid:      "111",
				UserId:    "phippy",
				TokenType: v1.TokenType_TOKEN_TYPE_API,
			},
			req: &v1.TokenServiceUpdateRequest{
				Uuid: "222",
				ProjectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				TenantRoles: map[string]v1.TenantRole{},
			},
			state: state{
				adminSubjects: []string{},
				projectRoles: map[string]v1.ProjectRole{
					"kubies": v1.ProjectRole_PROJECT_ROLE_EDITOR,
				},
				tenantRoles: map[string]v1.TenantRole{},
			},
			wantErr:        true,
			wantErrMessage: `not_found: token not found`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(token.ContextWithToken(context.Background(), tt.sessionToken))
			defer cancel()

			s := miniredis.RunT(t)
			c := redis.NewClient(&redis.Options{Addr: s.Addr()})

			tokenStore := token.NewRedisStore(c)
			certStore := certs.NewRedisStore(&certs.Config{
				RedisClient: c,
			})

			if tt.tokenToUpdate != nil {
				err := tokenStore.Set(ctx, tt.tokenToUpdate)
				require.NoError(t, err)
			}

			rawService := New(Config{
				Log:           slog.Default(),
				TokenStore:    tokenStore,
				CertStore:     certStore,
				MasterClient:  nil,
				Issuer:        "http://test",
				AdminSubjects: tt.state.adminSubjects,
			})

			service, ok := rawService.(*tokenService)
			if !ok {
				t.Fatalf("want new token service to be tokenService, got: %T", rawService)
			}

			service.projectsAndTenantsGetter = func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error) {
				return &putil.ProjectsAndTenants{
					ProjectRoles: tt.state.projectRoles,
					TenantRoles:  tt.state.tenantRoles,
				}, nil
			}

			response, err := service.Update(ctx, connect.NewRequest(tt.req))
			switch {
			case tt.wantErr && err != nil:
				if dff := cmp.Diff(tt.wantErrMessage, err.Error()); dff != "" {
					t.Fatal(dff)
				}
			case tt.wantErr && err == nil:
				t.Fatalf("want error %q, got response %q", tt.wantErrMessage, response)
			case err != nil:
				t.Fatalf("want response, got error %q", err)

			default:
				got := response.Msg.Token
				assert.Equal(t, tt.wantToken.Uuid, got.Uuid, "uuid")
				assert.Equal(t, tt.wantToken.Description, got.Description, "description")
				assert.Equal(t, tt.wantToken.UserId, got.UserId, "user id")
				assert.Equal(t, tt.wantToken.TokenType, got.TokenType, "token type")
				assert.Equal(t, tt.wantToken.AdminRole, got.AdminRole, "admin role")
				assert.Equal(t, tt.wantToken.Permissions, got.Permissions, "permissions")
				assert.Equal(t, tt.wantToken.ProjectRoles, got.ProjectRoles, "project roles")
				assert.Equal(t, tt.wantToken.TenantRoles, got.TenantRoles, "tenant roles")
			}
		})
	}
}
