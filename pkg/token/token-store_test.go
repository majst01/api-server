package token

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	v1 "github.com/metal-stack/api/go/api/v1"
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

	johnDoeToken := &v1.Token{UserId: "john@doe.com", Uuid: "abc"}
	willSmithToken := &v1.Token{UserId: "will@smith.com", Uuid: "def"}
	frankZappaToken := &v1.Token{UserId: "frank@zappa.com", Uuid: "cde"}

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

func TestRedisStoreSetAndGet(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	store := NewRedisStore(c)

	now := time.Now()

	inTok := &v1.Token{
		Uuid:        "bd21fe60-047c-45aa-812d-adc44e098a38",
		UserId:      "john@doe.com",
		Description: "abc",
		Permissions: []*v1.MethodPermission{
			{
				Subject: "a",
				Methods: []string{"b", "c"},
			},
		},
		Expires:   timestamppb.New(now),
		IssuedAt:  timestamppb.New(now),
		TokenType: v1.TokenType_TOKEN_TYPE_API,
		ProjectRoles: map[string]v1.ProjectRole{
			"8aa3f4c1-52a8-4656-86bc-4006ec016af6": v1.ProjectRole_PROJECT_ROLE_OWNER,
		},
		TenantRoles: map[string]v1.TenantRole{
			"foo@github": v1.TenantRole_TENANT_ROLE_OWNER,
			"bar@github": v1.TenantRole_TENANT_ROLE_EDITOR,
			"42@github":  v1.TenantRole_TENANT_ROLE_VIEWER,
		},
		AdminRole: pointer.Pointer(v1.AdminRole_ADMIN_ROLE_VIEWER),
	}

	err := store.Set(ctx, inTok)
	require.NoError(t, err)

	require.NoError(t, store.Migrate(ctx, slog.Default()))

	outTok, err := store.Get(ctx, inTok.UserId, inTok.Uuid)
	require.NoError(t, err)
	require.NotNil(t, outTok)

	assert.Equal(t, inTok, outTok)
}
