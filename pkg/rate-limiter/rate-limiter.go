package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/metal-stack/api-server/pkg/service/method"
	v1 "github.com/metal-stack/api/go/metalstack/api/v1"
)

const (
	separator = ":"
	prefix    = "ratelimiter_"
	halfHour  = 30 * time.Minute
)

type (
	errRatelimitReached struct {
		limit int
	}

	ratelimiter struct {
		client *redis.Client
	}
)

func New(client *redis.Client) *ratelimiter {
	return &ratelimiter{
		client: client,
	}
}

// CheckLimitTokenAccess enforces maxRequestsPerMinute for the given token
func (r *ratelimiter) CheckLimitTokenAccess(ctx context.Context, t *v1.Token, maxRequestsPerMinute int) (bool, error) {
	if method.IsAdminToken(t) {
		// admin tokens should not have a rate-limit (i.e. the accounting uses the api excessively to report usages)
		return true, nil
	}

	return r.limit(ctx, keyFromToken(t), maxRequestsPerMinute)
}

// CheckLimitTokenAccess enforces maxRequestsPerMinute for the given token
func (r *ratelimiter) CheckLimitUnauthenticatedAccess(ctx context.Context, ip string, maxRequestsPerMinute int) (bool, error) {
	return r.limit(ctx, keyFromIP(ip), maxRequestsPerMinute)
}

func (r *ratelimiter) limit(ctx context.Context, k string, maxRequestsPerMinute int) (bool, error) {
	raw, err := r.client.Get(ctx, k).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, err
	}

	if err == nil {
		count, err := strconv.Atoi(raw)
		if err != nil {
			return false, fmt.Errorf("limit count is malformed: %w", err)
		}

		if count > maxRequestsPerMinute {
			return false, &errRatelimitReached{limit: maxRequestsPerMinute}
		}
	}

	// Redis Pipeline will create a new key prefix every minute
	pipe := r.client.TxPipeline()

	_ = pipe.Incr(ctx, k)
	_ = pipe.Expire(ctx, k, halfHour) // expiration must be less than 60 minutes

	_, err = pipe.Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("unable to increment rate-limit count: %w", err)
	}

	return true, nil
}

func keyFromToken(t *v1.Token) string {
	return prefix + t.UserId + separator + t.Uuid + separator + strconv.Itoa(time.Now().Minute())
}

func keyFromIP(ip string) string {
	return prefix + ip + separator + strconv.Itoa(time.Now().Minute())
}

// Error implements the error interface
func (e *errRatelimitReached) Error() string {
	return fmt.Sprintf("you have reached the per-minute API rate limit (limit: %d)", e.limit)
}

// Unwrap implements the errorsas interface
func (e *errRatelimitReached) Unwrap() error {
	return nil
}
