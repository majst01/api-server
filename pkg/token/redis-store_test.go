package token

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	allowed, err := store.Allowed(ctx, johnDoeToken)
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, err = store.Allowed(ctx, frankZappaToken)
	require.NoError(t, err)
	require.False(t, allowed)

	tokens, err := store.List(ctx, "john@doe.com")
	require.NoError(t, err)
	assert.Len(t, tokens, 1)

	allTokens, err := store.AdminList(ctx)
	require.NoError(t, err)
	assert.Len(t, allTokens, 2)

	err = store.Revoke(ctx, johnDoeToken)
	require.NoError(t, err)

	allowed, err = store.Allowed(ctx, johnDoeToken)
	require.NoError(t, err)
	require.False(t, allowed)

}
