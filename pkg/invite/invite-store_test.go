package invite

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/go-cmp/cmp"
	apiv1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/metal-lib/pkg/testcommon"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_validateInviteSecret(t *testing.T) {
	secret, err := GenerateInviteSecret()
	require.NoError(t, err)

	tests := []struct {
		name    string
		s       string
		wantErr error
	}{
		{
			name:    "valid secret key returned from generate func",
			s:       secret,
			wantErr: nil,
		},
		{
			name:    "unexpected length",
			s:       "foo",
			wantErr: fmt.Errorf("unexpected invite secret length"),
		},
		{
			name:    "unexpected chars",
			s:       strings.Repeat("*", inviteSecretLength),
			wantErr: fmt.Errorf("invite secret contains unexpected characters: '*'"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInviteSecret(tt.s)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}

func Test_ProjectInvite(t *testing.T) {
	secret, err := GenerateInviteSecret()
	require.NoError(t, err)

	var (
		now   = timestamppb.Now()
		mr    = miniredis.RunT(t)
		store = NewProjectRedisStore(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
		ctx   = context.Background()

		i = &apiv1.ProjectInvite{
			Secret:      secret,
			Project:     "foo",
			Role:        apiv1.ProjectRole_PROJECT_ROLE_EDITOR,
			Joined:      false,
			ProjectName: "bar",
			Tenant:      "tenant",
			TenantName:  "tenant with name",
			ExpiresAt:   now,
			JoinedAt:    nil,
		}
	)
	defer mr.Close()

	err = store.SetInvite(ctx, i)
	require.NoError(t, err)

	got, err := store.GetInvite(ctx, i.Secret)
	require.NoError(t, err)
	require.Equal(t, i, got)

	gotList, err := store.ListInvites(ctx, i.Project)
	require.NoError(t, err)
	require.Equal(t, []*apiv1.ProjectInvite{i}, gotList)

	err = store.DeleteInvite(ctx, i)
	require.NoError(t, err)

	gotList, err = store.ListInvites(ctx, i.Project)
	require.NoError(t, err)
	require.Empty(t, gotList)
}

func Test_TenantInvite(t *testing.T) {
	secret, err := GenerateInviteSecret()
	require.NoError(t, err)

	var (
		now   = timestamppb.Now()
		mr    = miniredis.RunT(t)
		store = NewTenantRedisStore(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
		ctx   = context.Background()

		i = &apiv1.TenantInvite{
			Secret:           secret,
			TargetTenant:     "target",
			Role:             apiv1.TenantRole_TENANT_ROLE_EDITOR,
			Joined:           false,
			TargetTenantName: "target with name",
			Tenant:           "tenant",
			TenantName:       "tenant with name",
			ExpiresAt:        now,
			JoinedAt:         nil,
		}
	)
	defer mr.Close()

	err = store.SetInvite(ctx, i)
	require.NoError(t, err)

	got, err := store.GetInvite(ctx, i.Secret)
	require.NoError(t, err)
	require.Equal(t, i, got)

	gotList, err := store.ListInvites(ctx, i.TargetTenant)
	require.NoError(t, err)
	require.Equal(t, []*apiv1.TenantInvite{i}, gotList)

	err = store.DeleteInvite(ctx, i)
	require.NoError(t, err)

	gotList, err = store.ListInvites(ctx, i.Tenant)
	require.NoError(t, err)
	require.Empty(t, gotList)
}
