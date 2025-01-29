package ip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/db/generic"
	"github.com/metal-stack/api-server/pkg/db/metal"
	apiv1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/api/go/metalstack/api/v1/apiv1connect"
	ipamv1 "github.com/metal-stack/go-ipam/api/v1"
	ipamv1connect "github.com/metal-stack/go-ipam/api/v1/apiv1connect"
	"github.com/metal-stack/metal-lib/pkg/tag"
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

	// Project is already checked in the tenant-interceptor, ipam must not be consulted
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
	req := rq.Msg

	q := &query{
		IPServiceListRequest: &apiv1.IPServiceListRequest{
			Ip:               req.Ip,
			Name:             req.Name,
			Network:          req.Network,
			Project:          req.Project,
			Type:             req.Type,
			Af:               req.Af,
			Uuid:             req.Uuid,
			MachineId:        req.MachineId,
			ParentPrefixCidr: req.ParentPrefixCidr,
			Tags:             req.Tags,
		},
	}

	resp, err := i.ds.IP().Search(ctx, q)
	if err != nil {
		return nil, err
	}

	var res []*apiv1.IP
	for _, ip := range resp {

		m := tag.NewTagMap(ip.Tags)
		if _, ok := m.Value(tag.MachineID); ok {
			// we do not want to show machine ips (e.g. firewall public ips)
			continue
		}

		res = append(res, convert(ip))
	}

	return connect.NewResponse(&apiv1.IPServiceListResponse{
		Ips: res,
	}), nil
}

// Delete implements v1.IPServiceServer
func (i *ipServiceServer) Delete(ctx context.Context, rq *connect.Request[apiv1.IPServiceDeleteRequest]) (*connect.Response[apiv1.IPServiceDeleteResponse], error) {
	i.log.Debug("delete", "ip", rq)
	req := rq.Msg

	resp, err := i.ds.IP().Get(ctx, req.Ip)
	if err != nil {
		if generic.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, err
	}

	// TODO also delete in go-ipam in one transaction
	err = i.ds.IP().Delete(ctx, &metal.IP{IPAddress: req.Ip})
	if err != nil {
		if generic.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, err
	}
	_, err = i.ipam.ReleaseIP(ctx, connect.NewRequest(&ipamv1.ReleaseIPRequest{Ip: req.Ip, PrefixCidr: resp.ParentPrefixCidr}))
	if err != nil {
		var connectErr *connect.Error
		if errors.As(err, &connectErr) {
			if connectErr.Code() != connect.CodeNotFound {
				return nil, err
			}
		}
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
	return connect.NewResponse(&apiv1.IPServiceAllocateResponse{}), nil
}

// Static implements v1.IPServiceServer
func (i *ipServiceServer) Update(ctx context.Context, rq *connect.Request[apiv1.IPServiceUpdateRequest]) (*connect.Response[apiv1.IPServiceUpdateResponse], error) {
	i.log.Debug("update", "ip", rq)

	req := rq.Msg

	old, err := i.ds.IP().Get(ctx, req.Ip)
	if err != nil { // TODO not found
		if generic.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
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
		var t metal.IPType
		switch req.Type.String() {
		case apiv1.IPType_IP_TYPE_EPHEMERAL.String():
			t = metal.Ephemeral
		case apiv1.IPType_IP_TYPE_STATIC.String():
			t = metal.Static
		case apiv1.IPType_IP_TYPE_UNSPECIFIED.String():
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("ip type cannot be unspecified: %s", req.Type))
		}
		newIP.Type = t
	}
	newIP.Tags = req.Tags

	err = i.ds.IP().Update(ctx, &newIP, old)
	if err != nil {
		if generic.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, err
	}

	stored, err := i.ds.IP().Get(ctx, req.Ip)
	if err != nil {
		if generic.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, err
	}

	return connect.NewResponse(&apiv1.IPServiceUpdateResponse{Ip: convert(stored)}), nil
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

type query struct {
	*apiv1.IPServiceListRequest
}

func (p query) Query(q r.Term) *r.Term {
	// Project is mandatory
	q = q.Filter(func(row r.Term) r.Term {
		return row.Field("projectid").Eq(p.Project)
	})

	if p.Ip != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("id").Eq(*p.Ip)
		})
	}

	if p.Uuid != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("allocationuuid").Eq(*p.Uuid)
		})
	}

	if p.Name != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("name").Eq(*p.Name)
		})
	}

	if p.Network != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("networkid").Eq(*p.Network)
		})
	}

	if p.ParentPrefixCidr != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("prefix").Eq(*p.ParentPrefixCidr)
		})
	}

	if p.MachineId != nil {
		p.Tags = append(p.Tags, fmt.Sprintf("%s=%s", tag.MachineID, *p.MachineId))
	}

	for _, t := range p.Tags {
		t := t
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("tags").Contains(r.Expr(t))
		})
	}

	if p.Type != nil {
		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("type").Eq(p.Type.String())
		})
	}

	if p.Af != nil {
		var separator string
		switch p.Af.String() {
		case apiv1.IPAddressFamily_IP_ADDRESS_FAMILY_V4.String():
			separator = "\\."
		case apiv1.IPAddressFamily_IP_ADDRESS_FAMILY_V6.String():
			separator = ":"
		}

		q = q.Filter(func(row r.Term) r.Term {
			return row.Field("id").Match(separator)
		})
	}

	return &q
}
