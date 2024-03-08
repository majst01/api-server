package token

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/permissions"
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
		samplePermissions = []*v1.MethodPermission{
			{Subject: "project-a", Methods: []string{"/api.v1.ClusterService/List"}},
		}
		sampleRoles = []*v1.TokenRole{
			{Subject: "default-project@test", Role: v1.OWNER},
		}
	)

	got, err := service.CreateConsoleTokenWithoutPermissionCheck(ctx, "test", &connect.Request[v1.TokenServiceCreateRequest]{
		Msg: &v1.TokenServiceCreateRequest{
			Description: "test",
			Permissions: samplePermissions,
			Roles:       sampleRoles,
			Expires:     durationpb.New(1 * time.Minute),
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
	assert.Equal(t, samplePermissions, got.Msg.GetToken().GetPermissions())
	assert.Equal(t, sampleRoles, got.Msg.GetToken().GetRoles())

	// verifying keydb entry
	err = tokenStore.Set(ctx, got.Msg.GetToken())
	require.NoError(t, err)

	// listing tokens

	tokenList, err := service.List(token.ContextWithTokenClaims(ctx, claims), &connect.Request[v1.TokenServiceListRequest]{})
	require.NoError(t, err)

	require.NotNil(t, tokenList)
	require.NotNil(t, tokenList.Msg)

	require.Len(t, tokenList.Msg.Tokens, 1)

	// Check allowed
	allowed, err := tokenStore.Allowed(ctx, got.Msg.GetToken())
	require.NoError(t, err)
	require.True(t, allowed)

	// Check allowed after revocation
	err = tokenStore.Revoke(ctx, got.Msg.GetToken())
	require.NoError(t, err)

	allowed, err = tokenStore.Allowed(ctx, got.Msg.GetToken())
	require.NoError(t, err)
	require.False(t, allowed)

	// List must now be empty
	tokenList, err = service.List(token.ContextWithTokenClaims(ctx, claims), &connect.Request[v1.TokenServiceListRequest]{})
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
		claims         *token.Claims
		req            *v1.TokenServiceCreateRequest
		adminSubjects  []string
		wantErr        bool
		wantErrMessage string
	}{
		{
			name: "simple token with empty permissions and roles",
			claims: &token.Claims{
				Permissions: token.MethodPermissions{
					"": []string{""},
				},
				Roles: token.TokenRoles{},
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
			claims: &token.Claims{
				Roles: map[string]string{
					"ae8d2493-41ec-4efd-bbb4-81085b20b6fe": "owner",
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
			name: "simple token with no permissions but tenant role",
			claims: &token.Claims{
				Roles: map[string]string{
					"john@github": "owner",
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
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{},
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
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{},
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
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{},
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
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{},
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
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{
						"/api.v1.ClusterService/Create",
						"/api.v1.ClusterService/Get",
						"/api.v1.ClusterService/Delete",
					},
				},
				Roles: token.TokenRoles{},
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
			claims: &token.Claims{
				Permissions: token.MethodPermissions{
					"": []string{""},
				},
				Roles: token.TokenRoles{},
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
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get a cluster",
				Permissions: []*v1.MethodPermission{
					{
						Subject: "abc",
						Methods: []string{"/api.v1.ClusterService/Get"},
					},
				},
				Roles: []*v1.TokenRole{
					{
						Subject: "john@github",
						Role:    "owner",
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested subject:\"john@github\" is not allowed",
		},
		{
			name: "token has to low role",
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{
					"company-a@github": "viewer",
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
				Roles: []*v1.TokenRole{
					{
						Subject: "company-a@github",
						Role:    "editor",
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested role:\"editor\" is higher than allowed role:\"viewer\"",
		},
		{
			name: "token request has unknown role",
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{
					"company-a@github": "viewer",
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
				Roles: []*v1.TokenRole{
					{
						Subject: "company-a@github",
						Role:    "nob",
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "requested role:\"nob\" is not known",
		},
		{
			name: "token has unknown role",
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Permissions: token.MethodPermissions{
					"abc": []string{"/api.v1.ClusterService/Get"},
				},
				Roles: token.TokenRoles{
					"company-a@github": "nob",
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
				Roles: []*v1.TokenRole{
					{
						Subject: "company-a@github",
						Role:    "viewer",
					},
				},
				Expires: inOneHour,
			},
			adminSubjects:  []string{},
			wantErr:        true,
			wantErrMessage: "claim role:\"nob\" is not known",
		},
		// AdminSubjects
		{
			name:          "token requested admin role but is not allowed",
			adminSubjects: []string{},
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Roles: token.TokenRoles{
					"company-a@github": "editor",
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				Roles: []*v1.TokenRole{
					{
						Subject: "*",
						Role:    "admin",
					},
				},
				Expires: inOneHour,
			},
			wantErr:        true,
			wantErrMessage: "requested subject:\"*\" is not allowed",
		},
		{
			name: "token requested admin role but is member of admin orga",
			adminSubjects: []string{
				"company-a@github",
			},
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Roles: token.TokenRoles{
					"company-a@github": "viewer",
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				Roles: []*v1.TokenRole{
					{
						Subject: "*",
						Role:    "admin",
					},
				},
				Expires: inOneHour,
			},
			wantErr:        true,
			wantErrMessage: "requested subject:\"*\" is not allowed",
		},
		{
			name: "token requested admin role but is editor in admin orga",
			adminSubjects: []string{
				"company-a@github",
			},
			claims: &token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "john@github",
				},
				Roles: token.TokenRoles{
					"company-a@github": "editor",
				},
			},
			req: &v1.TokenServiceCreateRequest{
				Description: "i want to get admin access",
				Roles: []*v1.TokenRole{
					{
						Subject: "*",
						Role:    "admin",
					},
				},
				Expires: inOneHour,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenCreate(tt.claims, tt.req, servicePermissions, tt.adminSubjects)
			if err != nil && !tt.wantErr {
				t.Errorf("validateTokenCreate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.wantErrMessage != err.Error() {
				t.Errorf("validateTokenCreate() error.Error = %s, wantErrMsg %s", err.Error(), tt.wantErrMessage)
			}
		})
	}
}
