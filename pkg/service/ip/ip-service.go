package ip

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/db/generic"
	"github.com/metal-stack/api-server/pkg/db/metal"
	apiv1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/api/go/metalstack/api/v1/apiv1connect"
	ipamv1connect "github.com/metal-stack/go-ipam/api/v1/apiv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

type Config struct {
	Log       *slog.Logger
	Datastore *generic.Datastore
	Ipam      ipamv1connect.IpamServiceClient
}
type ipServiceServer struct {
	log  *slog.Logger
	ds   *generic.Datastore
	ipam ipamv1connect.IpamServiceClient
}

func New(c Config) apiv1connect.IPServiceHandler {
	return &ipServiceServer{
		log: c.Log.WithGroup("ipService"),
		ds:  c.Datastore,
	}
}

func (i *ipServiceServer) Get(ctx context.Context, rq *connect.Request[apiv1.IPServiceGetRequest]) (*connect.Response[apiv1.IPServiceGetResponse], error) {
	i.log.Debug("get", "ip", rq)
	req := rq.Msg

	resp, err := i.ds.IP().Get(ctx, req.Ip)
	if err != nil {
		if generic.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, err
	}

	return connect.NewResponse(&apiv1.IPServiceGetResponse{
		Ip: convert(resp),
	}), nil
}

// List implements v1.IPServiceServer
func (i *ipServiceServer) List(ctx context.Context, rq *connect.Request[apiv1.IPServiceListRequest]) (*connect.Response[apiv1.IPServiceListResponse], error) {
	i.log.Debug("list", "ip", rq)
	// req := rq.Msg

	// resp, err := i.ds.IP().Search(ctx, query)
	// if err != nil {
	// 	return nil, err
	// }

	// var res []*apiv1.IP
	// for _, ipElem := range resp.Payload {

	// 	m := tag.NewTagMap(ipElem.Tags)
	// 	if _, ok := m.Value(tag.MachineID); ok {
	// 		// we do not want to show machine ips (e.g. firewall public ips)
	// 		continue
	// 	}

	// 	res = append(res, convert(ipElem))
	// }

	// return connect.NewResponse(&apiv1.IPServiceListResponse{
	// 	Ips: res,
	// }), nil

	return nil, nil
}

// Delete implements v1.IPServiceServer
func (i *ipServiceServer) Delete(ctx context.Context, rq *connect.Request[apiv1.IPServiceDeleteRequest]) (*connect.Response[apiv1.IPServiceDeleteResponse], error) {
	i.log.Debug("delete", "ip", rq)
	req := rq.Msg

	resp, err := i.ds.IP().Get(ctx, req.Ip)
	if err != nil { // TODO notfound
		return nil, err
	}

	err = i.ds.IP().Delete(ctx, &metal.IP{IPAddress: req.Ip})
	if err != nil { // TODO notfound
		return nil, err
	}
	return connect.NewResponse(&apiv1.IPServiceDeleteResponse{
		Ip: convert(resp),
	}), nil
}

// Allocate implements v1.IPServiceServer
func (i *ipServiceServer) Allocate(ctx context.Context, rq *connect.Request[apiv1.IPServiceAllocateRequest]) (*connect.Response[apiv1.IPServiceAllocateResponse], error) {
	i.log.Debug("allocate", "ip", rq)
	// req := rq.Msg

	// ipType := models.V1IPBaseTypeEphemeral
	// if req.Type != apiv1.IPType_IP_TYPE_UNSPECIFIED.Enum() {
	// 	ipType = models.V1IPAllocateRequestTypeStatic
	// }

	// ipResp, err := i.m.IP().AllocateIP(ip.NewAllocateIPParams().WithBody(&models.V1IPAllocateRequest{
	// 	Description: req.Description,
	// 	Name:        req.Name,
	// 	Networkid:   &req.Network,
	// 	Projectid:   &req.Project,
	// 	Type:        pointer.Pointer(string(ipType)),
	// 	Tags:        req.Tags,
	// }), nil)
	// if err != nil {
	// 	var conflict *ip.AllocateIPConflict
	// 	if errors.As(err, &conflict) {
	// 		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	// 	}

	// 	return nil, err
	// }

	// return connect.NewResponse(&apiv1.IPServiceAllocateResponse{Ip: convert(ipResp.Payload)}), nil
	return nil, nil
}

// Static implements v1.IPServiceServer
func (i *ipServiceServer) Update(ctx context.Context, rq *connect.Request[apiv1.IPServiceUpdateRequest]) (*connect.Response[apiv1.IPServiceUpdateResponse], error) {
	i.log.Debug("update", "ip", rq)

	req := rq.Msg

	var t metal.IPType
	switch req.Type {
	case apiv1.IPType_IP_TYPE_EPHEMERAL.Enum():
		t = metal.Ephemeral
	case apiv1.IPType_IP_TYPE_STATIC.Enum():
		t = metal.Static
	case apiv1.IPType_IP_TYPE_UNSPECIFIED.Enum():
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("ip type cannot be unspecified: %s", req.Type))
	}

	old, err := i.ds.IP().Get(ctx, req.Ip)
	if err != nil { // TODO not found
		return nil, err
	}

	newIP := *old

	if req.Description != nil {
		newIP.Description = *req.Description
	}
	if req.Name != nil {
		newIP.Name = *req.Name
	}
	if req.Type != nil {
		newIP.Type = t
	}
	newIP.Tags = req.Tags

	err = i.ds.IP().Update(ctx, &newIP, old)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&apiv1.IPServiceUpdateResponse{Ip: convert(&newIP)}), nil
}

func convert(resp *metal.IP) *apiv1.IP {
	t := apiv1.IPType_IP_TYPE_UNSPECIFIED
	switch resp.Type {
	case metal.Ephemeral:
		t = apiv1.IPType_IP_TYPE_EPHEMERAL
	case metal.Static:
		t = apiv1.IPType_IP_TYPE_STATIC
	}

	ip := &apiv1.IP{
		Ip:          resp.IPAddress,
		Uuid:        resp.AllocationUUID,
		Name:        resp.Name,
		Description: resp.Description,
		Network:     resp.NetworkID,
		Project:     resp.ProjectID,
		Type:        t,
		Tags:        resp.Tags,
		CreatedAt:   timestamppb.New(time.Time(resp.Created)),
		UpdatedAt:   timestamppb.New(time.Time(resp.Changed)),
		DeletedAt:   &timestamppb.Timestamp{},
	}
	return ip
}

func generateTerm(q r.Term, p apiv1.IPServiceListRequest) *r.Term {
	if p.Ip != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("id").Eq(*p.Ip)
		})
	}

	// if p.AllocationUUID != nil {
	// 	q = q.Filter(func(row r.Term) r.Term {
	// 		return row.Field("allocationuuid").Eq(*p.AllocationUUID)
	// 	})
	// }

	// if p.Name != nil {
	// 	q = q.Filter(func(row r.Term) r.Term {
	// 		return row.Field("name").Eq(*p.Name)
	// 	})
	// }

	// if p.Project != nil {
	// 	q = q.Filter(func(row r.Term) r.Term {
	// 		return row.Field("projectid").Eq(*p.ProjectID)
	// 	})
	// }

	if p.Network != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("networkid").Eq(*p.Network)
		})
	}

	// if p.ParentPrefixCidr != nil {
	// 	q = q.Filter(func(row r.Term) r.Term {
	// 		return row.Field("networkprefix").Eq(*p.ParentPrefixCidr)
	// 	})
	// }

	// if p.MachineID != nil {
	// 	p.Tags = append(p.Tags, metal.IpTag(tag.MachineID, *p.MachineID))
	// }

	// for _, t := range p.Tags {
	// 	t := t
	// 	q = q.Filter(func(row r.Term) r.Term {
	// 		return row.Field("tags").Contains(r.Expr(t))
	// 	})
	// }

	if p.Type != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("type").Eq(p.Type.String())
		})
	}

	// if p.AddressFamily != nil {
	// 	separator := "."
	// 	af := metal.ToAddressFamily(*p.AddressFamily)
	// 	switch af {
	// 	case metal.IPv4AddressFamily:
	// 		separator = "\\."
	// 	case metal.IPv6AddressFamily:
	// 		separator = ":"
	// 	}

	// 	q = q.Filter(func(row r.Term) r.Term {
	// 		return row.Field("id").Match(separator)
	// 	})
	// }

	return &q
}
