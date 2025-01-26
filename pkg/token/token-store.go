package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/redis/go-redis/v9"
)

const (
	separator = ":"
	prefix    = "tokenstore_"
)

var (
	ErrTokenNotFound = redis.Nil
)

type TokenStore interface {
	Set(ctx context.Context, token *v1.Token) error
	Get(ctx context.Context, userid, tokenid string) (*v1.Token, error)
	List(ctx context.Context, userid string) ([]*v1.Token, error)
	AdminList(ctx context.Context) ([]*v1.Token, error)
	Revoke(ctx context.Context, userid, tokenid string) error
	Migrate(ctx context.Context, log *slog.Logger) error
}

type redisStore struct {
	client *redis.Client
}

func key(userid, tokenid string) string {
	return prefix + userid + separator + tokenid
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
	encoded, err := json.Marshal(toInternal(token))
	if err != nil {
		return fmt.Errorf("unable to encode token: %w", err)
	}

	_, err = r.client.Set(ctx, key(token.UserId, token.Uuid), string(encoded), time.Until(token.Expires.AsTime())).Result()
	if err != nil {
		return err
	}

	return nil
}

func (r *redisStore) Get(ctx context.Context, userid, tokenid string) (*v1.Token, error) {
	encoded, err := r.client.Get(ctx, key(userid, tokenid)).Result()
	if err != nil {
		return nil, err
	}

	var t token
	err = json.Unmarshal([]byte(encoded), &t)
	if err != nil {
		return nil, err
	}

	return toExternal(&t), nil
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

		var t token
		err = json.Unmarshal([]byte(encoded), &t)
		if err != nil {
			return nil, err
		}

		res = append(res, toExternal(&t))
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

		var t token
		err = json.Unmarshal([]byte(encoded), &t)
		if err != nil {
			return nil, err
		}

		res = append(res, toExternal(&t))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (r *redisStore) Revoke(ctx context.Context, userid, tokenid string) error {
	_, err := r.client.Del(ctx, key(userid, tokenid)).Result()
	return err
}

func (r *redisStore) Migrate(ctx context.Context, log *slog.Logger) error {
	tokens, err := r.AdminList(ctx)
	if err != nil {
		return err
	}

	var errs []error

	for range tokens {
		// possible future migrations can go here
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
