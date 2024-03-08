package tenant

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"

	tutil "github.com/metal-stack/api-server/pkg/tenant"
)

type Config struct {
	Log          *slog.Logger
	MasterClient mdc.Client
}
type tenantServiceServer struct {
	log          *slog.Logger
	masterClient mdc.Client
}

// RemoveMember implements apiv1connect.TenantServiceHandler.
func (u *tenantServiceServer) RemoveMember(context.Context, *connect.Request[v1.TenantServiceRemoveMemberRequest]) (*connect.Response[v1.TenantServiceRemoveMemberResponse], error) {
	panic("unimplemented")
}

func New(c Config) apiv1connect.TenantServiceHandler {
	return &tenantServiceServer{
		log:          c.Log.WithGroup("tenantService"),
		masterClient: c.MasterClient,
	}
}

func (u *tenantServiceServer) Create(ctx context.Context, rq *connect.Request[v1.TenantServiceCreateRequest]) (*connect.Response[v1.TenantServiceCreateResponse], error) {
	u.log.Debug("create", "tenant", rq)
	req := rq.Msg

	tenant := tutil.Convert(req.Tenant)

	tcr, err := u.masterClient.Tenant().Create(ctx, &mdcv1.TenantCreateRequest{Tenant: tenant})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.TenantServiceCreateResponse{Tenant: tutil.ConvertFromTenant(tcr.Tenant)}), nil
}

// CreateOrUpdate implements v1.TenantServiceServer
// Only called from login process
func (u *tenantServiceServer) CreateOrUpdate(ctx context.Context, rq *connect.Request[v1.TenantServiceCreateOrUpdateRequest]) (*connect.Response[v1.TenantServiceCreateOrUpdateResponse], error) {
	req := rq.Msg
	newTenant := req.Tenant

	ugr, err := u.Get(ctx, connect.NewRequest(&v1.TenantServiceGetRequest{Login: newTenant.Login}))
	if err != nil {
		if connect.CodeOf(err) != connect.CodeNotFound {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable fetch existing tenant:%w", err))
		}
		ucr, err := u.Create(ctx, connect.NewRequest(&v1.TenantServiceCreateRequest{Tenant: newTenant}))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to create a tenant:%w", err))
		}
		return connect.NewResponse(&v1.TenantServiceCreateOrUpdateResponse{Tenant: ucr.Msg.Tenant}), nil
	}
	u.log.Info("tenant already exists", "tenant", ugr.Msg.Tenant.Login)

	oldTenant := ugr.Msg.Tenant

	tur := &v1.TenantServiceUpdateRequest{
		Login: newTenant.Login,
	}

	if newTenant.AvatarUrl != oldTenant.AvatarUrl {
		tur.AvatarUrl = &newTenant.AvatarUrl
	}
	if newTenant.Email != oldTenant.Email {
		tur.Email = &newTenant.Email
	}
	if newTenant.Name != oldTenant.Name {
		tur.Name = &newTenant.Name
	}

	uur, err := u.Update(ctx, connect.NewRequest(tur))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to update tenant:%w", err))
	}
	return connect.NewResponse(&v1.TenantServiceCreateOrUpdateResponse{Tenant: uur.Msg.Tenant}), nil

}

func (u *tenantServiceServer) Get(ctx context.Context, rq *connect.Request[v1.TenantServiceGetRequest]) (*connect.Response[v1.TenantServiceGetResponse], error) {
	u.log.Debug("get", "tenant", rq)
	req := rq.Msg

	tgr, err := u.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{Id: req.Login})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&v1.TenantServiceGetResponse{Tenant: tutil.ConvertFromTenant(tgr.Tenant)}), nil
}

func (u *tenantServiceServer) Update(ctx context.Context, rq *connect.Request[v1.TenantServiceUpdateRequest]) (*connect.Response[v1.TenantServiceUpdateResponse], error) {
	u.log.Debug("update", "tenant", rq)
	req := rq.Msg

	tgr, err := u.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{Id: req.Login})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	tenant := tutil.ConvertFromTenant(tgr.Tenant)
	// FIXME check for all non nil fields
	if req.AvatarUrl != nil {
		tenant.AvatarUrl = *req.AvatarUrl
	}
	if req.Email != nil {
		tenant.Email = *req.Email
	}
	if req.Name != nil {
		tenant.Name = *req.Name
	}

	t := tutil.Convert(tenant)
	t.Meta.Version = tgr.Tenant.Meta.Version

	tur, err := u.masterClient.Tenant().Update(ctx, &mdcv1.TenantUpdateRequest{Tenant: t})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.TenantServiceUpdateResponse{Tenant: tutil.ConvertFromTenant(tur.Tenant)}), nil
}

func (u *tenantServiceServer) Delete(ctx context.Context, rq *connect.Request[v1.TenantServiceDeleteRequest]) (*connect.Response[v1.TenantServiceDeleteResponse], error) {
	u.log.Debug("delete", "tenant", rq)
	req := rq.Msg

	tdr, err := u.masterClient.Tenant().Delete(ctx, &mdcv1.TenantDeleteRequest{Id: req.Login})
	if err != nil {
		return nil, err
	}
	u.log.Debug("deleted", "tenant", tdr.Tenant)
	return connect.NewResponse(&v1.TenantServiceDeleteResponse{Tenant: tutil.ConvertFromTenant(tdr.Tenant)}), nil
}

// Invite implements apiv1connect.TenantServiceHandler.
func (u *tenantServiceServer) Invite(context.Context, *connect.Request[v1.TenantServiceInviteRequest]) (*connect.Response[v1.TenantServiceInviteResponse], error) {
	panic("unimplemented")
}

// InviteAccept implements apiv1connect.TenantServiceHandler.
func (u *tenantServiceServer) InviteAccept(context.Context, *connect.Request[v1.TenantServiceInviteAcceptRequest]) (*connect.Response[v1.TenantServiceInviteAcceptResponse], error) {
	panic("unimplemented")
}

// InviteDelete implements apiv1connect.TenantServiceHandler.
func (u *tenantServiceServer) InviteDelete(context.Context, *connect.Request[v1.TenantServiceInviteDeleteRequest]) (*connect.Response[v1.TenantServiceInviteDeleteResponse], error) {
	panic("unimplemented")
}

// InviteGet implements apiv1connect.TenantServiceHandler.
func (u *tenantServiceServer) InviteGet(context.Context, *connect.Request[v1.TenantServiceInviteGetRequest]) (*connect.Response[v1.TenantServiceInviteGetResponse], error) {
	panic("unimplemented")
}

// InvitesList implements apiv1connect.TenantServiceHandler.
func (u *tenantServiceServer) InvitesList(context.Context, *connect.Request[v1.TenantServiceInvitesListRequest]) (*connect.Response[v1.TenantServiceInvitesListResponse], error) {
	panic("unimplemented")
}
