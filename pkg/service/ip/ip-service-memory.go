package ip

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/metal-stack/api-server/pkg/service/store"
	v1 "github.com/metal-stack/api/go/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ipMemoryServiceServer struct {
	log   *slog.Logger
	store store.Store[*v1.IP]
}

func (i *ipMemoryServiceServer) Get(ctx context.Context, rq *connect.Request[v1.IPServiceGetRequest]) (*connect.Response[v1.IPServiceGetResponse], error) {
	i.log.Debug("get", "ip", rq)
	req := rq.Msg
	ip, err := i.store.Get(req.Uuid)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.IPServiceGetResponse{
		Ip: ip,
	}), nil
}

// List implements v1.IPServiceServer
func (i *ipMemoryServiceServer) List(ctx context.Context, rq *connect.Request[v1.IPServiceListRequest]) (*connect.Response[v1.IPServiceListResponse], error) {
	i.log.Debug("list", "ip", rq)
	req := rq.Msg
	ip, err := i.store.List(&req.Project)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.IPServiceListResponse{
		Ips: ip,
	}), nil
}

// Delete implements v1.IPServiceServer
func (i *ipMemoryServiceServer) Delete(ctx context.Context, rq *connect.Request[v1.IPServiceDeleteRequest]) (*connect.Response[v1.IPServiceDeleteResponse], error) {
	i.log.Debug("delete", "ip", rq)
	req := rq.Msg
	ip, err := i.store.Delete(req.Uuid)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.IPServiceDeleteResponse{
		Ip: ip,
	}), nil
}

// Allocate implements v1.IPServiceServer
func (i *ipMemoryServiceServer) Allocate(ctx context.Context, rq *connect.Request[v1.IPServiceAllocateRequest]) (*connect.Response[v1.IPServiceAllocateResponse], error) {
	i.log.Debug("allocate", "ip", rq)
	req := rq.Msg
	random, err := randomIPFromRange("212.1.2.0/24")
	if err != nil {
		return nil, err
	}

	ipType := v1.IPType_IP_TYPE_EPHEMERAL
	if req.Static {
		ipType = v1.IPType_IP_TYPE_STATIC
	}

	ip := &v1.IP{
		Uuid:        uuid.NewString(),
		Ip:          random.String(),
		Type:        ipType,
		Name:        req.Name,
		Network:     "random internet",
		Project:     req.Project,
		Tags:        req.Tags,
		Description: req.Description,
	}
	err = i.store.Set(ip)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.IPServiceAllocateResponse{Ip: ip}), nil
}

// Static implements v1.IPServiceServer
func (i *ipMemoryServiceServer) Update(ctx context.Context, rq *connect.Request[v1.IPServiceUpdateRequest]) (*connect.Response[v1.IPServiceUpdateResponse], error) {
	i.log.Debug("update", "ip", rq)

	req := rq.Msg
	ip, err := i.store.Get(req.Ip.Uuid)
	if err != nil {
		return nil, err
	}
	ip.Name = req.Ip.Name
	ip.Description = req.Ip.Description
	ip.Tags = req.Ip.Tags
	ip.Type = req.Ip.Type
	ip.UpdatedAt = timestamppb.Now()
	err = i.store.Set(ip)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.IPServiceUpdateResponse{Ip: ip}), nil
}

func randomIPFromRange(cidr string) (net.IP, error) {

GENERATE:

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// The number of leading 1s in the mask
	ones, _ := ipnet.Mask.Size()
	quotient := ones / 8
	remainder := ones % 8

	// create random 4-byte byte slice
	r := make([]byte, 4)
	_, _ = rand.Read(r)

	for i := 0; i <= quotient; i++ {
		if i == quotient {
			shifted := byte(r[i]) >> remainder
			r[i] = ^ipnet.IP[i] & shifted
		} else {
			r[i] = ipnet.IP[i]
		}
	}
	ip := net.IPv4(r[0], r[1], r[2], r[3])

	if ip.Equal(ipnet.IP) /*|| ip.Equal(broadcast) */ {
		// we got unlucky. The host portion of our ipv4 address was
		// either all 0s (the network address) or all 1s (the broadcast address)
		goto GENERATE
	}
	return ip, nil
}
