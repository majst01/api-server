package token

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
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
		Log:        slog.Default(),
		TokenStore: tokenStore,
		CertStore:  certStore,
		Issuer:     "http://test",
	})

	var (
		samplePermissions = []*apiv1.MethodPermission{
			{Subject: "project-a", Methods: []string{"/api.v1.ClusterService/List"}},
		}
	)

	got, err := service.CreateConsoleTokenWithoutPermissionCheck(ctx, "test", &connect.Request[apiv1.TokenServiceCreateRequest]{
		Msg: &apiv1.TokenServiceCreateRequest{
			Description: "test",
			Permissions: samplePermissions,
			ProjectRoles: map[string]apiv1.ProjectRole{
				"b1584890-1300-47ad-bdb1-10c32e43ed31": apiv1.ProjectRole_PROJECT_ROLE_OWNER,
			},
			TenantRoles: map[string]apiv1.TenantRole{
				"b1584890-1300-47ad-bdb1-10c32e43ed31": apiv1.TenantRole_TENANT_ROLE_OWNER,
			},
			Expires: durationpb.New(1 * time.Minute),
		},
	})
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

	tokenList, err := service.List(token.ContextWithToken(ctx, got.Msg.Token), &connect.Request[apiv1.TokenServiceListRequest]{})
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
	tokenList, err = service.List(token.ContextWithToken(ctx, got.Msg.Token), &connect.Request[apiv1.TokenServiceListRequest]{})
	require.NoError(t, err)

	require.NotNil(t, tokenList)
	require.NotNil(t, tokenList.Msg)
	require.Empty(t, tokenList.Msg.Tokens)
}

func Test_validateTokenCreate(t *testing.T) {
	servicePermissions := permissions.GetServicePermissions()
	inOneHour := durationpb.New(time.Hour)
	oneHundredDays := durationpb.New(100 * 24 * time.Hour)
	tests := []struct {
		name           string
		token          *apiv1.Token
		req            *apiv1.TokenServiceCreateRequest
		adminSubjects  []string
		wantErr        bool
		wantErrMessage string
	}{
		{
			name: "simple token with empty permissions and roles",
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "",
						Methods: []string{""},
					},
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i don't need any permissions",
				Expires:     inOneHour,
			},
			adminSubjects: []string{},
			wantErr:       false,
		},
		// Inherited Permissions
		{
			name: "simple token with no permissions but project role",
			token: &apiv1.Token{
				ProjectRoles: map[string]apiv1.ProjectRole{
					"ae8d2493-41ec-4efd-bbb4-81085b20b6fe": apiv1.ProjectRole_PROJECT_ROLE_OWNER,
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get a cluster for this project",
				Permissions: []*apiv1.MethodPermission{
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
			token: &apiv1.Token{
				TenantRoles: map[string]apiv1.TenantRole{
					"john@github": apiv1.TenantRole_TENANT_ROLE_OWNER,
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to update payments",
				Permissions: []*apiv1.MethodPermission{
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
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*apiv1.MethodPermission{
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
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*apiv1.MethodPermission{
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
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*apiv1.MethodPermission{
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
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to list clusters",
				Permissions: []*apiv1.MethodPermission{
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
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
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
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get and list clusters",
				Permissions: []*apiv1.MethodPermission{
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
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "",
						Methods: []string{""},
					},
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
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
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]apiv1.TenantRole{
					"john@github": apiv1.TenantRole_TENANT_ROLE_OWNER,
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested tenant:\"john@github\" is not allowed",
		},
		{
			name: "token has to low role",
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]apiv1.TenantRole{
					"company-a@github": apiv1.TenantRole_TENANT_ROLE_VIEWER,
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]apiv1.TenantRole{
					"company-a@github": apiv1.TenantRole_TENANT_ROLE_EDITOR,
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested role:\"TENANT_ROLE_EDITOR\" is higher than allowed role:\"TENANT_ROLE_VIEWER\"",
		},
		{
			name: "token request has unspecified role",
			token: &apiv1.Token{
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]apiv1.TenantRole{
					"company-a@github": apiv1.TenantRole_TENANT_ROLE_VIEWER,
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*apiv1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				TenantRoles: map[string]apiv1.TenantRole{
					"company-a@github": apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED,
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
			token: &apiv1.Token{
				TenantRoles: map[string]apiv1.TenantRole{
					"company-a@github": apiv1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				AdminRole:   pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_VIEWER),
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
			token: &apiv1.Token{
				TenantRoles: map[string]apiv1.TenantRole{
					"company-a@github": apiv1.TenantRole_TENANT_ROLE_VIEWER,
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				AdminRole:   pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR),
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
			token: &apiv1.Token{
				UserId: "company-a@github",
				TenantRoles: map[string]apiv1.TenantRole{
					"company-a@github": apiv1.TenantRole_TENANT_ROLE_EDITOR,
				},
			},
			req: &apiv1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				AdminRole:   pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR),
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
