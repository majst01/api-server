package ip

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/service/store"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
)

type Config struct {
	Log *slog.Logger
}
type ipServiceServer struct {
	log *slog.Logger
}

func New(c Config) apiv1connect.IPServiceHandler {
	return &ipMemoryServiceServer{
		log:   c.Log.WithGroup("ipMemoryService"),
		store: store.NewMemoryStore[*v1.IP](nil),
	}
}

func (i *ipServiceServer) Get(ctx context.Context, rq *connect.Request[v1.IPServiceGetRequest]) (*connect.Response[v1.IPServiceGetResponse], error) {
	i.log.Debug("get", "ip", rq)
	return nil, nil
}

// List implements v1.IPServiceServer
func (i *ipServiceServer) List(ctx context.Context, rq *connect.Request[v1.IPServiceListRequest]) (*connect.Response[v1.IPServiceListResponse], error) {
	i.log.Debug("list", "ip", rq)
	return nil, nil
}

// Delete implements v1.IPServiceServer
func (i *ipServiceServer) Delete(ctx context.Context, rq *connect.Request[v1.IPServiceDeleteRequest]) (*connect.Response[v1.IPServiceDeleteResponse], error) {
	i.log.Debug("delete", "ip", rq)
	return nil, nil
}

// Allocate implements v1.IPServiceServer
func (i *ipServiceServer) Allocate(ctx context.Context, rq *connect.Request[v1.IPServiceAllocateRequest]) (*connect.Response[v1.IPServiceAllocateResponse], error) {
	i.log.Debug("allocate", "ip", rq)
	return nil, nil

}

// Static implements v1.IPServiceServer
func (i *ipServiceServer) Update(ctx context.Context, rq *connect.Request[v1.IPServiceUpdateRequest]) (*connect.Response[v1.IPServiceUpdateResponse], error) {
	i.log.Debug("update", "ip", rq)
	return nil, nil
}
