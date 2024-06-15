package ratelimiter

import (
	"context"
	"testing"
	"time"

	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	apiv1 "github.com/metal-stack/api/go/api/v1"
)

func Test_ratelimiter_CheckLimitTokenAccess(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: s.Addr()})

	limiter := ratelimiter{
		client: c,
	}

	privateKey, err := certs.NewRedisStore(&certs.Config{
		RedisClient: c,
	}).LatestPrivate(context.Background())
	require.NoError(t, err)

	_, tok, err := token.NewJWT(apiv1.TokenType_TOKEN_TYPE_CONSOLE, "userid", "issuer", 30*time.Minute, privateKey)
	require.NoError(t, err)

	for i := 0; i <= 20; i++ {
		allowed, err := limiter.CheckLimitTokenAccess(ctx, tok, 20)
		require.NoError(t, err)
		assert.True(t, allowed)
	}

	allowed, err := limiter.CheckLimitTokenAccess(ctx, tok, 20)
	require.Error(t, err)
	require.ErrorContains(t, err, "you have reached the per-minute API rate limit (limit: 20)")
	assert.False(t, allowed)
}
