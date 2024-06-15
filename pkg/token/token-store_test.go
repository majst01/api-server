package token

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRedisStore(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	store := NewRedisStore(c)

	johnDoeToken := &apiv1.Token{UserId: "john@doe.com", Uuid: "abc"}
	willSmithToken := &apiv1.Token{UserId: "will@smith.com", Uuid: "def"}
	frankZappaToken := &apiv1.Token{UserId: "frank@zappa.com", Uuid: "cde"}

	err := store.Set(ctx, johnDoeToken)
	require.NoError(t, err)

	err = store.Set(ctx, willSmithToken)
	require.NoError(t, err)

	tok, err := store.Get(ctx, johnDoeToken.UserId, johnDoeToken.Uuid)
	require.NoError(t, err)
	require.NotNil(t, tok)

	tok, err = store.Get(ctx, frankZappaToken.UserId, frankZappaToken.Uuid)
	require.Error(t, err)
	require.Nil(t, tok)

	tokens, err := store.List(ctx, "john@doe.com")
	require.NoError(t, err)
	assert.Len(t, tokens, 1)

	allTokens, err := store.AdminList(ctx)
	require.NoError(t, err)
	assert.Len(t, allTokens, 2)

	err = store.Revoke(ctx, johnDoeToken.UserId, johnDoeToken.Uuid)
	require.NoError(t, err)

	tok, err = store.Get(ctx, johnDoeToken.UserId, johnDoeToken.Uuid)
	require.Error(t, err)
	require.Nil(t, tok)
}

func TestRedisStoreMigrate(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	store := NewRedisStore(c)

	now := time.Now()

	tok := &tokenCompat{
		Uuid:        "bd21fe60-047c-45aa-812d-adc44e098a38",
		UserId:      "john@doe.com",
		Description: "abc",
		Permissions: []methodPermission{
			{
				Subject: "a",
				Methods: []string{"b", "c"},
			},
		},
		Expires:   timestamppb.New(now),
		IssuedAt:  timestamppb.New(now),
		TokenType: int32(apiv1.TokenType_TOKEN_TYPE_API),
		Roles: []*tokenRole{
			{
				Subject: "8aa3f4c1-52a8-4656-86bc-4006ec016af6",
				Role:    "owner",
			},
			{
				Subject: "foo@github",
				Role:    "editor",
			},
			{
				Subject: "ca16fb8c-5917-44a3-9698-67403954dd9a",
				Role:    "editor",
			},
			{
				Subject: "ea1e9e13-e222-498e-8c7b-8d366b13418e",
				Role:    "viewer",
			},
			{
				Subject: "*",
				Role:    "admin",
			},
		},
	}

	encoded, err := json.Marshal(tok)
	require.NoError(t, err)

	_, err = c.Set(ctx, key(tok.UserId, tok.Uuid), string(encoded), time.Hour).Result()
	require.NoError(t, err)

	err = store.Migrate(ctx, slog.Default())
	require.NoError(t, err)

	v1Token, err := store.Get(ctx, tok.UserId, tok.Uuid)
	require.NoError(t, err)
	require.NotNil(t, v1Token)

	assert.Equal(t, tok.Uuid, v1Token.Uuid)
	assert.Equal(t, tok.UserId, v1Token.UserId)
	assert.WithinRange(t, v1Token.Expires.AsTime(), tok.Expires.AsTime().Add(-1*time.Second), tok.Expires.AsTime().Add(1*time.Second))
	assert.WithinRange(t, v1Token.IssuedAt.AsTime(), tok.IssuedAt.AsTime().Add(-1*time.Second), tok.IssuedAt.AsTime().Add(1*time.Second))
	assert.Equal(t, tok.Description, v1Token.Description)
	assert.Equal(t, tok.TokenType, int32(v1Token.TokenType))
	require.NotNil(t, v1Token.AdminRole)
	assert.Equal(t, apiv1.AdminRole_ADMIN_ROLE_EDITOR, *v1Token.AdminRole)
	require.Len(t, v1Token.Permissions, len(tok.Permissions))
	assert.Equal(t, tok.Permissions[0].Methods, v1Token.Permissions[0].Methods)
	assert.Equal(t, tok.Permissions[0].Subject, v1Token.Permissions[0].Subject)
	require.Len(t, v1Token.ProjectRoles, 3)
	require.Len(t, v1Token.TenantRoles, 1)
	require.Contains(t, v1Token.ProjectRoles, "8aa3f4c1-52a8-4656-86bc-4006ec016af6")
	require.Contains(t, v1Token.ProjectRoles, "ca16fb8c-5917-44a3-9698-67403954dd9a")
	require.Contains(t, v1Token.ProjectRoles, "ea1e9e13-e222-498e-8c7b-8d366b13418e")
	require.Contains(t, v1Token.TenantRoles, "foo@github")
	assert.Equal(t, apiv1.ProjectRole_PROJECT_ROLE_OWNER, v1Token.ProjectRoles["8aa3f4c1-52a8-4656-86bc-4006ec016af6"])
	assert.Equal(t, apiv1.ProjectRole_PROJECT_ROLE_EDITOR, v1Token.ProjectRoles["ca16fb8c-5917-44a3-9698-67403954dd9a"])
	assert.Equal(t, apiv1.ProjectRole_PROJECT_ROLE_VIEWER, v1Token.ProjectRoles["ea1e9e13-e222-498e-8c7b-8d366b13418e"])
	assert.Equal(t, apiv1.TenantRole_TENANT_ROLE_EDITOR, v1Token.TenantRoles["foo@github"])
}

func TestRedisStoreSetAndGet(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	store := NewRedisStore(c)

	now := time.Now()

	inTok := &apiv1.Token{
		Uuid:        "bd21fe60-047c-45aa-812d-adc44e098a38",
		UserId:      "john@doe.com",
		Description: "abc",
		Permissions: []*apiv1.MethodPermission{
			{
				Subject: "a",
				Methods: []string{"b", "c"},
			},
		},
		Expires:   timestamppb.New(now),
		IssuedAt:  timestamppb.New(now),
		TokenType: apiv1.TokenType_TOKEN_TYPE_API,
		ProjectRoles: map[string]apiv1.ProjectRole{
			"8aa3f4c1-52a8-4656-86bc-4006ec016af6": apiv1.ProjectRole_PROJECT_ROLE_OWNER,
		},
		TenantRoles: map[string]apiv1.TenantRole{
			"foo@github": apiv1.TenantRole_TENANT_ROLE_OWNER,
			"bar@github": apiv1.TenantRole_TENANT_ROLE_EDITOR,
			"42@github":  apiv1.TenantRole_TENANT_ROLE_VIEWER,
		},
		AdminRole: pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_VIEWER),
	}

	err := store.Set(ctx, inTok)
	require.NoError(t, err)

	require.NoError(t, store.Migrate(ctx, slog.Default()))

	outTok, err := store.Get(ctx, inTok.UserId, inTok.Uuid)
	require.NoError(t, err)
	require.NotNil(t, outTok)

	assert.Equal(t, inTok, outTok)
}

func TestRedisStoreCompatGet(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	store := NewRedisStore(c)

	oldToken := `{"uuid":"76490acc-8973-4ed5-849d-b78c16219f92","user_id":"john@doe.com","description":"admin cli access","roles":[{"subject":"*","role":"admin"}],"expires":{"seconds":1719055487,"nanos":82280882},"issued_at":{"seconds":1716463487,"nanos":82280882},"token_type":1}` //nolint:gosec

	_, err := c.Set(ctx, key("john@doe.com", "76490acc-8973-4ed5-849d-b78c16219f92"), string(oldToken), time.Until(time.Now().Add(10*time.Minute))).Result()
	require.NoError(t, err)

	tok, err := store.Get(ctx, "john@doe.com", "76490acc-8973-4ed5-849d-b78c16219f92")
	require.NoError(t, err)

	expires := time.Unix(1719055487, 82280882)
	issuedAt := time.Unix(1716463487, 82280882)

	assert.Equal(t, &apiv1.Token{
		Uuid:         "76490acc-8973-4ed5-849d-b78c16219f92",
		UserId:       "john@doe.com",
		Description:  "admin cli access",
		Expires:      timestamppb.New(expires),
		IssuedAt:     timestamppb.New(issuedAt),
		TokenType:    apiv1.TokenType_TOKEN_TYPE_API,
		ProjectRoles: map[string]apiv1.ProjectRole{},
		TenantRoles:  map[string]apiv1.TenantRole{},
		AdminRole:    pointer.Pointer(apiv1.AdminRole_ADMIN_ROLE_EDITOR),
	}, tok)
}
