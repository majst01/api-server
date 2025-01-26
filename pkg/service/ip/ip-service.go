package ip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	metalgo "github.com/metal-stack/metal-go"
	"github.com/metal-stack/metal-go/api/client/ip"
	"github.com/metal-stack/metal-go/api/models"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/pkg/tag"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Config struct {
	Log         *slog.Logger
	MetalClient metalgo.Client
}
type ipServiceServer struct {
	log *slog.Logger
	m   metalgo.Client
}

func New(c Config) apiv1connect.IPServiceHandler {
	return &ipServiceServer{
		log: c.Log.WithGroup("ipService"),
		m:   c.MetalClient,
	}
}

func (i *ipServiceServer) Get(ctx context.Context, rq *connect.Request[apiv1.IPServiceGetRequest]) (*connect.Response[apiv1.IPServiceGetResponse], error) {
	i.log.Debug("get", "ip", rq)
	req := rq.Msg

	i.m.IP().FindIP(ip.NewFindIPParamsWithContext(ctx).WithID(req.Uuid), nil)
	ip, err := i.get(req.Uuid)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&apiv1.IPServiceGetResponse{
		Ip: ip,
	}), nil
}

func (i *ipServiceServer) get(uuid string) (*apiv1.IP, error) {
	resp, err := i.m.IP().FindIPs(ip.NewFindIPsParams().WithBody(&models.V1IPFindRequest{
		Allocationuuid: uuid,
	}), nil)
	if err != nil {
		return nil, err
	}

	if len(resp.Payload) != 1 {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("ip not found: %s", uuid))
	}

	return fromMetalIP(resp.Payload[0]), nil
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

		res = append(res, fromMetalIP(ipElem))
	}

	return connect.NewResponse(&apiv1.IPServiceListResponse{
		Ips: res,
	}), nil
}

// Delete implements v1.IPServiceServer
func (i *ipServiceServer) Delete(ctx context.Context, rq *connect.Request[apiv1.IPServiceDeleteRequest]) (*connect.Response[apiv1.IPServiceDeleteResponse], error) {
	i.log.Debug("delete", "ip", rq)
	req := rq.Msg

	iptodelete, err := i.get(req.Uuid)
	if err != nil {
		return nil, err
	}

	resp, err := i.m.IP().FreeIP(ip.NewFreeIPParams().WithID(iptodelete.Ip), nil)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&apiv1.IPServiceDeleteResponse{
		Ip: fromMetalIP(resp.Payload),
	}), nil
}

// Allocate implements v1.IPServiceServer
func (i *ipServiceServer) Allocate(ctx context.Context, rq *connect.Request[apiv1.IPServiceAllocateRequest]) (*connect.Response[apiv1.IPServiceAllocateResponse], error) {
	i.log.Debug("allocate", "ip", rq)
	req := rq.Msg

	ipType := models.V1IPBaseTypeEphemeral
	if req.Static {
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

	return connect.NewResponse(&apiv1.IPServiceAllocateResponse{Ip: fromMetalIP(ipResp.Payload)}), nil
}

// Static implements v1.IPServiceServer
func (i *ipServiceServer) Update(ctx context.Context, rq *connect.Request[apiv1.IPServiceUpdateRequest]) (*connect.Response[apiv1.IPServiceUpdateResponse], error) {
	i.log.Debug("update", "ip", rq)

	req := rq.Msg

	var t string
	switch req.Ip.Type {
	case apiv1.IPType_IP_TYPE_EPHEMERAL:
		t = models.V1IPBaseTypeEphemeral
	case apiv1.IPType_IP_TYPE_STATIC:
		t = models.V1IPBaseTypeStatic
	case apiv1.IPType_IP_TYPE_UNSPECIFIED:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("ip type cannot be unspecified: %s", req.Ip.Type))
	}

	updatedIP, err := i.m.IP().UpdateIP(ip.NewUpdateIPParams().WithBody(&models.V1IPUpdateRequest{
		Description: req.Ip.Description,
		Ipaddress:   &req.Ip.Ip,
		Name:        req.Ip.Name,
		Tags:        req.Ip.Tags,
		Type:        &t,
	}), nil)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&apiv1.IPServiceUpdateResponse{Ip: fromMetalIP(updatedIP.Payload)}), nil
}

func fromMetalIP(ip *models.V1IPResponse) *apiv1.IP {
	var t apiv1.IPType
	if ip.Type != nil {
		switch *ip.Type {
		case models.V1IPBaseTypeEphemeral:
			t = apiv1.IPType_IP_TYPE_EPHEMERAL
		case models.V1IPAllocateRequestTypeStatic:
			t = apiv1.IPType_IP_TYPE_STATIC
		default:
			t = apiv1.IPType_IP_TYPE_UNSPECIFIED
		}
	}

	return &apiv1.IP{
		Uuid:        pointer.SafeDeref(ip.Allocationuuid),
		Ip:          pointer.SafeDeref(ip.Ipaddress),
		Name:        ip.Name,
		Description: ip.Description,
		Network:     pointer.SafeDeref(ip.Networkid),
		Project:     pointer.SafeDeref(ip.Projectid),
		Type:        t,
		Tags:        ip.Tags,
		CreatedAt:   timestamppb.New(time.Time(ip.Created)),
		UpdatedAt:   timestamppb.New(time.Time(ip.Changed)),
		DeletedAt:   &timestamppb.Timestamp{},
	}
}
