package token

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/redis/go-redis/v9"
)

const (
	separator = ":"
	prefix    = "tokenstore_"
)

type TokenStore interface {
	Set(ctx context.Context, token *v1.Token) error
	List(ctx context.Context, userid string) ([]*v1.Token, error)
	AdminList(ctx context.Context) ([]*v1.Token, error)
	Allowed(ctx context.Context, token *v1.Token) (bool, error)
	Revoke(ctx context.Context, token *v1.Token) error
}

type redisStore struct {
	client *redis.Client
}

func key(t *v1.Token) string {
	return prefix + t.UserId + separator + t.Uuid
}

func match(userid string) string {
	return prefix + userid + separator + "*"
}

func NewRedisStore(client *redis.Client) TokenStore {
	return &redisStore{
		client: client,
	}
}

func (r *redisStore) Set(ctx context.Context, token *v1.Token) error {
	encoded, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("unable to encode token: %w", err)
	}

	_, err = r.client.Set(ctx, key(token), string(encoded), time.Until(token.Expires.AsTime())).Result()
	if err != nil {
		return err
	}

	return nil
}

func (r *redisStore) List(ctx context.Context, userid string) ([]*v1.Token, error) {
	var (
		res  []*v1.Token
		iter = r.client.Scan(ctx, 0, match(userid), 0).Iterator()
	)

	for iter.Next(ctx) {
		encoded, err := r.client.Get(ctx, iter.Val()).Result()
		if err != nil {
			return nil, err
		}

		var token v1.Token
		err = json.Unmarshal([]byte(encoded), &token)
		if err != nil {
			return nil, err
		}

		res = append(res, &token)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (r *redisStore) AdminList(ctx context.Context) ([]*v1.Token, error) {
	var (
		res  []*v1.Token
		iter = r.client.Scan(ctx, 0, prefix+"*", 0).Iterator()
	)

	for iter.Next(ctx) {
		encoded, err := r.client.Get(ctx, iter.Val()).Result()
		if err != nil {
			return nil, err
		}

		var token v1.Token
		err = json.Unmarshal([]byte(encoded), &token)
		if err != nil {
			return nil, err
		}

		res = append(res, &token)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (r *redisStore) Allowed(ctx context.Context, token *v1.Token) (bool, error) {
	count, err := r.client.Exists(ctx, key(token)).Result()
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *redisStore) Revoke(ctx context.Context, token *v1.Token) error {
	_, err := r.client.Del(ctx, key(token)).Result()
	return err
}
