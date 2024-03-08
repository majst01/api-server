package token

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/redis/go-redis/v9"
)

type tokenWhitelistInterceptor struct {
	store TokenStore
	log   *slog.Logger
}

func NewTokenWhitelistInterceptor(log *slog.Logger, redisClient *redis.Client) *tokenWhitelistInterceptor {
	return &tokenWhitelistInterceptor{
		store: NewRedisStore(redisClient),
		log:   log,
	}
}

// WrapUnary will check if the rate limit for the given token is raised.
func (t *tokenWhitelistInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		err := t.filter(ctx)
		if err != nil {
			return nil, err
		}

		return next(ctx, req)
	})
}

func (t *tokenWhitelistInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return connect.StreamingClientFunc(func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		// TODO: do we need to do something here?
		return next(ctx, spec)
	})
}

func (t *tokenWhitelistInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		err := t.filter(ctx)
		if err != nil {
			return err
		}

		return next(ctx, conn)
	})
}

func (t *tokenWhitelistInterceptor) filter(ctx context.Context) error {
	claims, ok := TokenClaimsFromContext(ctx)
	if !ok || claims == nil {
		// if no token-based access, we let the request pass
		return nil
	}

	if claims.Type != apiv1.TokenType_TOKEN_TYPE_API.String() {
		// we only have api tokens on the whitelist
		// TODO: evaluate if it makes sense to do this for other token types as well
		return nil
	}

	allowed, err := t.store.Allowed(ctx, &apiv1.Token{
		Uuid:   claims.ID,
		UserId: claims.Subject,
	})
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	if allowed {
		return nil
	}

	return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("your token was revoked"))
}
