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
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"github.com/metal-stack/metal-go/api/client/ip"
	"github.com/metal-stack/metal-go/api/models"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/pkg/tag"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Config struct {
	Log       *slog.Logger
	Datastore *generic.Datastore
}
type ipServiceServer struct {
	log *slog.Logger
	ds  *generic.Datastore
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
	if err != nil { // TODO notfound
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

	ipfr := &models.V1IPFindRequest{
		Projectid: req.Project,
	}

	if req.Network != nil {
		ipfr.Networkid = *req.Network
	}

	resp, err := i.m.IP().FindIPs(ip.NewFindIPsParams().WithBody(ipfr), nil)
	if err != nil {
		return nil, err
	}

	var res []*apiv1.IP
	for _, ipElem := range resp.Payload {

		m := tag.NewTagMap(ipElem.Tags)
		if _, ok := m.Value(tag.MachineID); ok {
			// we do not want to show machine ips (e.g. firewall public ips)
			continue
		}

		res = append(res, convert(ipElem))
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
	req := rq.Msg

	ipType := models.V1IPBaseTypeEphemeral
	if req.Type != apiv1.IPType_IP_TYPE_UNSPECIFIED.Enum() {
		ipType = models.V1IPAllocateRequestTypeStatic
	}

	ipResp, err := i.m.IP().AllocateIP(ip.NewAllocateIPParams().WithBody(&models.V1IPAllocateRequest{
		Description: req.Description,
		Name:        req.Name,
		Networkid:   &req.Network,
		Projectid:   &req.Project,
		Type:        pointer.Pointer(string(ipType)),
		Tags:        req.Tags,
	}), nil)
	if err != nil {
		var conflict *ip.AllocateIPConflict
		if errors.As(err, &conflict) {
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		}

		return nil, err
	}

	return connect.NewResponse(&apiv1.IPServiceAllocateResponse{Ip: convert(ipResp.Payload)}), nil
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
