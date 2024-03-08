package project

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/redis/go-redis/v9"
)

const (
	inviteSecretLength  = 32
	inviteSecretLetters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

	separator     = ":"
	projectprefix = "invitestore_by_project_"
	secretprefix  = "invitestore_by_secret_"
)

type InviteStore interface {
	SetInvite(ctx context.Context, invite *apiv1.ProjectInvite) error
	GetInvite(ctx context.Context, secret string) (*apiv1.ProjectInvite, error)
	ListInvites(ctx context.Context, projectID string) ([]*apiv1.ProjectInvite, error)
	DeleteInvite(ctx context.Context, invite *apiv1.ProjectInvite) error
}

type redisStore struct {
	client *redis.Client
}

func NewRedisStore(client *redis.Client) InviteStore {
	return &redisStore{
		client: client,
	}
}

func projectkey(t *apiv1.ProjectInvite) string {
	return projectprefix + t.Project + separator + t.Secret
}

func secretkey(t *apiv1.ProjectInvite) string {
	return secretprefix + t.Secret
}

func matchProject(projectId string) string {
	return projectprefix + projectId + separator + "*"
}

func (r *redisStore) SetInvite(ctx context.Context, invite *apiv1.ProjectInvite) error {
	if err := validateInviteSecret(invite.Secret); err != nil {
		return err
	}

	encoded, err := json.Marshal(invite)
	if err != nil {
		return fmt.Errorf("unable to encode token: %w", err)
	}

	pipe := r.client.TxPipeline()

	_ = pipe.Set(ctx, projectkey(invite), string(encoded), time.Until(invite.ExpiresAt.AsTime()))
	_ = pipe.Set(ctx, secretkey(invite), string(encoded), time.Until(invite.ExpiresAt.AsTime()))

	_, err = pipe.Exec(ctx)

	return err
}

func (r *redisStore) ListInvites(ctx context.Context, projectid string) ([]*apiv1.ProjectInvite, error) {
	var (
		res  []*apiv1.ProjectInvite
		iter = r.client.Scan(ctx, 0, matchProject(projectid), 0).Iterator()
	)

	for iter.Next(ctx) {
		encoded, err := r.client.Get(ctx, iter.Val()).Result()
		if err != nil {
			return nil, err
		}

		var token apiv1.ProjectInvite
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

func (r *redisStore) DeleteInvite(ctx context.Context, invite *apiv1.ProjectInvite) error {
	if err := validateInviteSecret(invite.Secret); err != nil {
		return err
	}

	pipe := r.client.TxPipeline()

	_ = pipe.Del(ctx, secretkey(invite))
	_ = pipe.Del(ctx, projectkey(invite))

	_, err := pipe.Exec(ctx)

	return err
}

func (r *redisStore) GetInvite(ctx context.Context, secret string) (*apiv1.ProjectInvite, error) {
	if err := validateInviteSecret(secret); err != nil {
		return nil, err
	}

	encoded, err := r.client.Get(ctx, secretkey(&apiv1.ProjectInvite{Secret: secret})).Result()
	if err != nil {
		return nil, err
	}

	var invite apiv1.ProjectInvite
	err = json.Unmarshal([]byte(encoded), &invite)
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

// generateInviteSecret returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateInviteSecret() string {
	ret := make([]byte, inviteSecretLength)
	for i := range inviteSecretLength {
		num := rand.N(len(inviteSecretLetters))
		ret[i] = inviteSecretLetters[num]
	}

	return string(ret)
}

func validateInviteSecret(s string) error {
	if len(s) != inviteSecretLength {
		return fmt.Errorf("unexpected invite secret length")
	}

	for _, letter := range s {
		if !strings.ContainsRune(inviteSecretLetters, letter) {
			return fmt.Errorf("invite secret contains unexpected characters: %s", strconv.QuoteRune(letter))
		}
	}

	return nil
}
