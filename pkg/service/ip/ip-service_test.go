package ip

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/metal-stack/api-server/pkg/db/generic"
	"github.com/metal-stack/api-server/pkg/db/metal"
	"github.com/metal-stack/api-server/pkg/test"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_ipServiceServer_Get(t *testing.T) {
	container, c, err := test.StartRethink(t)
	require.NoError(t, err)
	defer func() {
		_ = container.Terminate(context.Background())
	}()

	ctx := context.Background()
	log := slog.Default()

	ds, err := generic.New(log, "metal", c)
	require.NoError(t, err)

	err = ds.IP().Create(ctx, &metal.IP{IPAddress: "1.2.3.4"})
	require.NoError(t, err)

	tests := []struct {
		name           string
		log            *slog.Logger
		ctx            context.Context
		rq             *apiv1.IPServiceGetRequest
		ds             *generic.Datastore
		want           *apiv1.IPServiceGetResponse
		wantReturnCode connect.Code
		wantErr        bool
	}{
		{
			name:    "get existing",
			log:     log,
			ctx:     ctx,
			rq:      &apiv1.IPServiceGetRequest{Ip: "1.2.3.4"},
			ds:      ds,
			want:    &apiv1.IPServiceGetResponse{Ip: &apiv1.IP{Ip: "1.2.3.4"}},
			wantErr: false,
		},
		{
			name:    "get non existing",
			log:     log,
			ctx:     ctx,
			rq:      &apiv1.IPServiceGetRequest{Ip: "1.2.3.5"},
			ds:      ds,
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &ipServiceServer{
				log: tt.log,
				ds:  tt.ds,
			}
			got, err := i.Get(tt.ctx, connect.NewRequest(tt.rq))
			if (err != nil) != tt.wantErr {
				t.Errorf("ipServiceServer.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want == nil && got == nil {
				return
			}
			if tt.want == nil && got != nil {
				t.Error("tt.want is nil but got is not")
				return
			}
			if !cmp.Equal(tt.want, got.Msg, cmp.Comparer(proto.Equal), cmpopts.IgnoreFields(apiv1.IP{}, "CreatedAt", "UpdatedAt", "DeletedAt")) {
				t.Errorf("ipServiceServer.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}
