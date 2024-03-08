package ratelimiter

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/token"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Log         *slog.Logger
	RedisClient *redis.Client

	MaxRequestsPerMinuteToken           int
	MaxRequestsPerMinuteUnauthenticated int
}

type ratelimitInterceptor struct {
	ratelimiter                         *ratelimiter
	maxRequestsPerMinuteToken           int
	maxRequestsPerMinuteUnauthenticated int
	log                                 *slog.Logger
}

func NewInterceptor(c *Config) *ratelimitInterceptor {
	return &ratelimitInterceptor{
		ratelimiter:                         New(c.RedisClient),
		maxRequestsPerMinuteToken:           c.MaxRequestsPerMinuteToken,
		maxRequestsPerMinuteUnauthenticated: c.MaxRequestsPerMinuteUnauthenticated,
		log:                                 c.Log,
	}
}

// WrapUnary will check if the rate limit for the given token is raised.
func (i *ratelimitInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		var (
			err        error
			claims, ok = token.TokenClaimsFromContext(ctx)
		)

		if ok && claims != nil {
			_, err = i.ratelimiter.CheckLimitTokenAccess(ctx, claims, i.maxRequestsPerMinuteToken)
		} else {
			clientIP, ok := extractClientIP(req.Header())
			if !ok {
				i.log.Warn("not finding original client ip in forwarding header, skipping rate-limiter for unauthenticated api access. please configure the ingress-controller to contain the original client ip address in the header.")
				return next(ctx, req)
			}

			_, err = i.ratelimiter.CheckLimitUnauthenticatedAccess(ctx, clientIP, i.maxRequestsPerMinuteUnauthenticated)
		}

		if err != nil {
			var ratelimiterError *errRatelimitReached
			if errors.As(err, &ratelimiterError) {
				return nil, connect.NewError(connect.CodeResourceExhausted, err)
			}
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		return next(ctx, req)
	})
}

func (i *ratelimitInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return connect.StreamingClientFunc(func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	})
}

func (i *ratelimitInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return next(ctx, conn)
	})
}

func extractClientIP(header http.Header) (string, bool) {
	ip := header.Get("X-Forwarded-For")
	if ip != "" {
		return ip, true
	}

	ip = header.Get("X-Real-Ip")
	if ip != "" {
		return ip, true
	}

	return "", false
}
