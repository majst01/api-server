package version

import (
	"context"
	"log/slog"
	"reflect"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/v"
)

func Test_versionServiceServer_Get(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		req      *v1.VersionServiceGetRequest
		log      *slog.Logger
		revision string
		version  string
		want     *v1.VersionServiceGetResponse
		wantErr  bool
	}{
		{
			name:     "simple",
			ctx:      context.Background(),
			req:      &v1.VersionServiceGetRequest{},
			revision: "abc",
			version:  "v0.0.1",
			log:      slog.Default(),
			want:     &v1.VersionServiceGetResponse{Version: &v1.Version{Version: "v0.0.1", Revision: "abc"}},
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v.Revision = tt.revision
			v.Version = tt.version
			a := &versionServiceServer{
				log: tt.log,
			}
			got, err := a.Get(tt.ctx, connect.NewRequest(tt.req))
			if (err != nil) != tt.wantErr {
				t.Errorf("versionServiceServer.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.Msg, tt.want) {
				t.Errorf("versionServiceServer.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}
