package invite

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	inviteSecretLength  = 32
	inviteSecretLetters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

	separator     = ":"
	projectprefix = "invitestore_by_project_"
	tenantprefix  = "invitestore_by_tenant_"
	secretprefix  = "invitestore_by_secret_"
)

var (
	ErrInviteNotFound = redis.Nil
)

type ProjectInviteStore interface {
	SetInvite(ctx context.Context, invite *apiv1.ProjectInvite) error
	GetInvite(ctx context.Context, secret string) (*apiv1.ProjectInvite, error)
	ListInvites(ctx context.Context, projectID string) ([]*apiv1.ProjectInvite, error)
	DeleteInvite(ctx context.Context, invite *apiv1.ProjectInvite) error
}
type TenantInviteStore interface {
	SetInvite(ctx context.Context, invite *apiv1.TenantInvite) error
	GetInvite(ctx context.Context, secret string) (*apiv1.TenantInvite, error)
	ListInvites(ctx context.Context, login string) ([]*apiv1.TenantInvite, error)
	DeleteInvite(ctx context.Context, invite *apiv1.TenantInvite) error
}

type invite interface {
	GetSecret() string
	GetExpiresAt() *timestamppb.Timestamp
}

type projectRedisStore struct {
	client *redis.Client
}
type tenantRedisStore struct {
	client *redis.Client
}

func NewProjectRedisStore(client *redis.Client) ProjectInviteStore {
	return &projectRedisStore{
		client: client,
	}
}
func NewTenantRedisStore(client *redis.Client) TenantInviteStore {
	return &tenantRedisStore{
		client: client,
	}
}

func projectkey(t *apiv1.ProjectInvite) string {
	return projectprefix + t.Project + separator + t.Secret
}
func tenantkey(t *apiv1.TenantInvite) string {
	return tenantprefix + t.TargetTenant + separator + t.Secret
}

func secretkey(secret string) string {
	return secretprefix + secret
}

func matchProject(projectId string) string {
	return projectprefix + projectId + separator + "*"
}
func matchTenant(tenantId string) string {
	return tenantprefix + tenantId + separator + "*"
}

// Project

func (r *projectRedisStore) SetInvite(ctx context.Context, i *apiv1.ProjectInvite) error {
	return set(ctx, r.client, i, func() string { return projectkey(i) })
}

func (r *projectRedisStore) ListInvites(ctx context.Context, projectid string) ([]*apiv1.ProjectInvite, error) {
	return list[*apiv1.ProjectInvite](ctx, r.client, matchProject(projectid))
}

func (r *projectRedisStore) DeleteInvite(ctx context.Context, i *apiv1.ProjectInvite) error {
	return delete(ctx, r.client, i, func() string { return projectkey(i) })
}

func (r *projectRedisStore) GetInvite(ctx context.Context, secret string) (*apiv1.ProjectInvite, error) {
	return get[*apiv1.ProjectInvite](ctx, r.client, secret)
}

// Tenant

func (r *tenantRedisStore) DeleteInvite(ctx context.Context, i *apiv1.TenantInvite) error {
	return delete(ctx, r.client, i, func() string { return tenantkey(i) })
}

func (r *tenantRedisStore) GetInvite(ctx context.Context, secret string) (*apiv1.TenantInvite, error) {
	return get[*apiv1.TenantInvite](ctx, r.client, secret)
}

func (r *tenantRedisStore) ListInvites(ctx context.Context, tenantID string) ([]*apiv1.TenantInvite, error) {
	return list[*apiv1.TenantInvite](ctx, r.client, matchTenant(tenantID))
}

func (r *tenantRedisStore) SetInvite(ctx context.Context, invite *apiv1.TenantInvite) error {
	return set(ctx, r.client, invite, func() string { return tenantkey(invite) })
}

func get[E any](ctx context.Context, c *redis.Client, secret string) (E, error) {
	var zero E

	if err := validateInviteSecret(secret); err != nil {
		return zero, err
	}

	encoded, err := c.Get(ctx, secretkey(secret)).Result()
	if err != nil {
		return zero, err
	}

	var e E
	err = json.Unmarshal([]byte(encoded), &e)
	if err != nil {
		return zero, err
	}

	return e, nil
}

func delete(ctx context.Context, c *redis.Client, i invite, keyFn func() string) error {
	if err := validateInviteSecret(i.GetSecret()); err != nil {
		return err
	}

	pipe := c.TxPipeline()

	_ = pipe.Del(ctx, secretkey(i.GetSecret()))
	_ = pipe.Del(ctx, keyFn())

	_, err := pipe.Exec(ctx)

	return err
}

func set(ctx context.Context, c *redis.Client, i invite, keyFn func() string) error {
	if i.GetExpiresAt() == nil {
		return fmt.Errorf("invite needs to have an expiration")
	}

	if err := validateInviteSecret(i.GetSecret()); err != nil {
		return err
	}

	encoded, err := json.Marshal(i)
	if err != nil {
		return fmt.Errorf("unable to encode invite: %w", err)
	}

	pipe := c.TxPipeline()

	_ = pipe.Set(ctx, keyFn(), string(encoded), time.Until(i.GetExpiresAt().AsTime()))
	_ = pipe.Set(ctx, secretkey(i.GetSecret()), string(encoded), time.Until(i.GetExpiresAt().AsTime()))

	_, err = pipe.Exec(ctx)

	return err
}

func list[E any](ctx context.Context, c *redis.Client, match string) ([]E, error) {
	var (
		res  []E
		iter = c.Scan(ctx, 0, match, 0).Iterator()
	)

	for iter.Next(ctx) {
		encoded, err := c.Get(ctx, iter.Val()).Result()
		if err != nil {
			return nil, err
		}

		var i E
		err = json.Unmarshal([]byte(encoded), &i)
		if err != nil {
			return nil, err
		}

		res = append(res, i)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

// GenerateInviteSecret returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateInviteSecret() (string, error) {
	ret := make([]byte, inviteSecretLength)
	for i := range inviteSecretLength {

		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(inviteSecretLetters))))
		if err != nil {
			return "", fmt.Errorf("unable to generate invite secret: %w", err)
		}

		ret[i] = inviteSecretLetters[num.Int64()]
	}

	return string(ret), nil
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
