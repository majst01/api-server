package version

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"github.com/metal-stack/v"
)

type Config struct {
	Log *slog.Logger
}
type versionServiceServer struct {
	log *slog.Logger
}

func New(c Config) apiv1connect.VersionServiceHandler {
	return &versionServiceServer{
		log: c.Log.WithGroup("versionService"),
	}
}

func (a *versionServiceServer) Get(ctx context.Context, rq *connect.Request[v1.VersionServiceGetRequest]) (*connect.Response[v1.VersionServiceGetResponse], error) {
	version := &v1.Version{
		Version:   v.Version,
		Revision:  v.Revision,
		GitSha1:   v.GitSHA1,
		BuildDate: v.BuildDate,
	}
	return connect.NewResponse(&v1.VersionServiceGetResponse{
		Version: version,
	}), nil
}
