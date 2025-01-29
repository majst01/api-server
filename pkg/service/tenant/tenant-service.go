package tenant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"connectrpc.com/connect"
	putil "github.com/metal-stack/api-server/pkg/project"
	msvc "github.com/metal-stack/api-server/pkg/service/method"
	apiv1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/api/go/metalstack/api/v1/apiv1connect"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/metal-stack/api-server/pkg/invite"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	"github.com/metal-stack/api-server/pkg/token"
)

type Config struct {
	Log          *slog.Logger
	MasterClient mdc.Client
	InviteStore  invite.TenantInviteStore
	TokenStore   token.TokenStore
}
type tenantServiceServer struct {
	log          *slog.Logger
	masterClient mdc.Client
	inviteStore  invite.TenantInviteStore
	tokenStore   token.TokenStore
}

type TenantService interface {
	apiv1connect.TenantServiceHandler
}

func New(c Config) TenantService {
	return &tenantServiceServer{
		log:          c.Log.WithGroup("tenantService"),
		masterClient: c.MasterClient,
		inviteStore:  c.InviteStore,
		tokenStore:   c.TokenStore,
	}
}

func (u *tenantServiceServer) List(ctx context.Context, rq *connect.Request[apiv1.TenantServiceListRequest]) (*connect.Response[apiv1.TenantServiceListResponse], error) {
	token, ok := token.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	var (
		req    = rq.Msg
		result []*apiv1.Tenant
	)

	projectsAndTenants, err := putil.GetProjectsAndTenants(ctx, u.masterClient, token.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error retrieving tenants from backend: %w", err))
	}

	for _, tenant := range projectsAndTenants.Tenants {
		// TODO: maybe we can pass the filter and not filter here

		if req.Name != nil && tenant.Name != *req.Name {
			continue
		}
		if req.Id != nil && tenant.Login != *req.Id {
			continue
		}

		result = append(result, tenant)
	}

	return connect.NewResponse(&apiv1.TenantServiceListResponse{Tenants: result}), nil
}

func (u *tenantServiceServer) Create(ctx context.Context, rq *connect.Request[apiv1.TenantServiceCreateRequest]) (*connect.Response[apiv1.TenantServiceCreateResponse], error) {
	u.log.Debug("create", "tenant", rq)

	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)
	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	resp, err := u.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{
		Id: t.UserId,
	})
	if err != nil {
		if mdcv1.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no tenant found with id %q: %w", t.UserId, err))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	ownTenant := resp.Tenant

	email := pointer.SafeDeref(req.Email)
	if email == "" && ownTenant.Meta != nil && ownTenant.Meta.Annotations != nil {
		email = ownTenant.Meta.Annotations[tutil.TagEmail]
		if email == "" {
			return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("email is required"))
		}
	}

	ann := map[string]string{
		tutil.TagEmail:   email,
		tutil.TagCreator: t.UserId,
	}

	if req.AvatarUrl != nil {
		ann[tutil.TagAvatarURL] = *req.AvatarUrl
	}
	if req.PhoneNumber != nil {
		ann[tutil.TagPhoneNumber] = *req.PhoneNumber
	}

	tcr, err := u.masterClient.Tenant().Create(ctx, &mdcv1.TenantCreateRequest{Tenant: &mdcv1.Tenant{
		Meta: &mdcv1.Meta{
			Annotations: ann,
		},
		Name:        req.Name,
		Description: pointer.SafeDeref(req.Description),
	}})
	if err != nil {
		return nil, err
	}

	_, err = u.masterClient.TenantMember().Create(ctx, &mdcv1.TenantMemberCreateRequest{
		TenantMember: &mdcv1.TenantMember{
			Meta: &mdcv1.Meta{
				Annotations: map[string]string{
					tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
				},
			},
			MemberId: t.UserId,
			TenantId: tcr.Tenant.Meta.Id,
		},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to store tenant member: %w", err))
	}

	return connect.NewResponse(&apiv1.TenantServiceCreateResponse{Tenant: tutil.ConvertFromTenant(tcr.Tenant)}), nil
}

func (u *tenantServiceServer) Get(ctx context.Context, rq *connect.Request[apiv1.TenantServiceGetRequest]) (*connect.Response[apiv1.TenantServiceGetResponse], error) {
	u.log.Debug("get", "tenant", rq)
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)
	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	resp, err := u.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{
		Id: req.Login,
	})
	if err != nil {
		if mdcv1.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no tenant found with id %q: %w", req.Login, err))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tenant := tutil.ConvertFromTenant(resp.Tenant)
	role := t.TenantRoles[req.Login]
	switch role {
	case apiv1.TenantRole_TENANT_ROLE_OWNER, apiv1.TenantRole_TENANT_ROLE_EDITOR, apiv1.TenantRole_TENANT_ROLE_VIEWER:
	case apiv1.TenantRole_TENANT_ROLE_GUEST:
		// guests only see a minimal subset of the tenant information, a guest is not part of the tenant!

		return connect.NewResponse(&apiv1.TenantServiceGetResponse{Tenant: &apiv1.Tenant{
			Login:       tenant.Login,
			Name:        tenant.Name,
			Email:       "",
			Description: tenant.Description,
			AvatarUrl:   tenant.AvatarUrl,
			CreatedBy:   "",
			CreatedAt:   tenant.CreatedAt,
			UpdatedAt:   tenant.UpdatedAt,
			DeletedAt:   tenant.DeletedAt,
		}, TenantMembers: nil}), nil
	case apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED:
		if msvc.IsAdminToken(t) {
			break
		}
		fallthrough
	default:
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("tenant role insufficient"))
	}

	tmlr, err := u.masterClient.Tenant().ListTenantMembers(ctx, &mdcv1.ListTenantMembersRequest{TenantId: req.Login})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to list tenant members: %w", err))
	}

	var tenantMembers []*apiv1.TenantMember
	for _, member := range tmlr.Tenants {
		tenantRole := tutil.TenantRoleFromMap(member.TenantAnnotations)
		if tenantRole == apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED {
			tenantRole = apiv1.TenantRole_TENANT_ROLE_GUEST
		}

		tenantMembers = append(tenantMembers, &apiv1.TenantMember{
			Id:         member.Tenant.Meta.Id,
			Role:       tenantRole,
			CreatedAt:  member.Tenant.Meta.CreatedTime,
			ProjectIds: member.ProjectIds,
		})

	}

	sort.Slice(tenantMembers, func(i, j int) bool {
		return tenantMembers[i].Id < tenantMembers[j].Id
	})

	return connect.NewResponse(&apiv1.TenantServiceGetResponse{Tenant: tenant, TenantMembers: tenantMembers}), nil
}

func (u *tenantServiceServer) Update(ctx context.Context, rq *connect.Request[apiv1.TenantServiceUpdateRequest]) (*connect.Response[apiv1.TenantServiceUpdateResponse], error) {
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
	if req.Description != nil {
		tenant.Description = *req.Description
	}
	t := tutil.Convert(tenant)
	t.Meta.Version = tgr.Tenant.Meta.Version

	tur, err := u.masterClient.Tenant().Update(ctx, &mdcv1.TenantUpdateRequest{Tenant: t})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.TenantServiceUpdateResponse{Tenant: tutil.ConvertFromTenant(tur.Tenant)}), nil
}

func (u *tenantServiceServer) Delete(ctx context.Context, rq *connect.Request[apiv1.TenantServiceDeleteRequest]) (*connect.Response[apiv1.TenantServiceDeleteResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)
	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	u.log.Debug("delete", "tenant", rq)

	if t.UserId == req.Login {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the personal tenant (default-tenant) cannot be deleted"))
	}

	pfr, err := u.masterClient.Project().Find(ctx, &mdcv1.ProjectFindRequest{
		TenantId: wrapperspb.String(req.Login),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to lookup projects: %w", err))
	}

	if len(pfr.Projects) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("there are still projects associated with this tenant, you need to delete them first"))
	}

	tdr, err := u.masterClient.Tenant().Delete(ctx, &mdcv1.TenantDeleteRequest{Id: req.Login})
	if err != nil {
		return nil, err
	}

	u.log.Debug("deleted", "tenant", tdr.Tenant)

	return connect.NewResponse(&apiv1.TenantServiceDeleteResponse{Tenant: tutil.ConvertFromTenant(tdr.Tenant)}), nil
}

func (u *tenantServiceServer) Invite(ctx context.Context, rq *connect.Request[apiv1.TenantServiceInviteRequest]) (*connect.Response[apiv1.TenantServiceInviteResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)
	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	tgr, err := u.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{
		Id: req.Login,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no tenant:%q found %w", req.Login, err))
	}

	invitee, err := u.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{
		Id: t.UserId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no tenant:%q found %w", t.UserId, err))
	}

	secret, err := invite.GenerateInviteSecret()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var (
		expiresAt = time.Now().Add(7 * 24 * time.Hour)
	)

	if req.Role == apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("tenant role must be specified"))
	}

	invite := &apiv1.TenantInvite{
		Secret:           secret,
		TargetTenant:     tgr.Tenant.Meta.Id,
		Role:             req.Role,
		Joined:           false,
		TargetTenantName: tgr.Tenant.Name,
		TenantName:       invitee.Tenant.Name,
		Tenant:           invitee.Tenant.Meta.Id,
		ExpiresAt:        timestamppb.New(expiresAt),
		JoinedAt:         &timestamppb.Timestamp{},
	}
	u.log.Info("tenant invitation created", "invitation", invite)

	err = u.inviteStore.SetInvite(ctx, invite)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TenantServiceInviteResponse{Invite: invite}), nil
}

func (u *tenantServiceServer) InviteAccept(ctx context.Context, rq *connect.Request[apiv1.TenantServiceInviteAcceptRequest]) (*connect.Response[apiv1.TenantServiceInviteAcceptResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)

	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	inv, err := u.inviteStore.GetInvite(ctx, req.Secret)
	if err != nil {
		if errors.Is(err, invite.ErrInviteNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the given invitation does not exist anymore"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tgr, err := u.masterClient.Tenant().Get(ctx, &mdcv1.TenantGetRequest{
		Id: t.UserId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no account:%q found %w", t.UserId, err))
	}

	invitee := tgr.Tenant

	if invitee.Meta.Id == inv.TargetTenant {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("an owner cannot accept invitations to own tenants"))
	}

	memberships, err := u.masterClient.TenantMember().Find(ctx, &mdcv1.TenantMemberFindRequest{
		TenantId: &inv.TargetTenant,
		MemberId: &invitee.Meta.Id,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if len(memberships.GetTenantMembers()) > 0 {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("%s is already member of tenant %s", invitee.Meta.Id, inv.TargetTenant))
	}

	err = u.inviteStore.DeleteInvite(ctx, inv)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	_, err = u.masterClient.TenantMember().Create(ctx, &mdcv1.TenantMemberCreateRequest{
		TenantMember: &mdcv1.TenantMember{
			Meta: &mdcv1.Meta{
				Annotations: map[string]string{
					tutil.TenantRoleAnnotation: inv.Role.String(),
				},
			},
			MemberId: invitee.Meta.Id,
			TenantId: inv.TargetTenant,
		},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to store tenant member: %w", err))
	}

	return connect.NewResponse(&apiv1.TenantServiceInviteAcceptResponse{Tenant: inv.TargetTenant, TenantName: inv.TargetTenantName}), nil
}

func (u *tenantServiceServer) InviteDelete(ctx context.Context, rq *connect.Request[apiv1.TenantServiceInviteDeleteRequest]) (*connect.Response[apiv1.TenantServiceInviteDeleteResponse], error) {
	var (
		req = rq.Msg
	)

	u.log.Debug("tenant invite delete", "req", req)

	err := u.inviteStore.DeleteInvite(ctx, &apiv1.TenantInvite{Secret: req.Secret, TargetTenant: req.Login})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	u.log.Debug("tenant invite deleted")

	return connect.NewResponse(&apiv1.TenantServiceInviteDeleteResponse{}), nil
}

func (u *tenantServiceServer) InviteGet(ctx context.Context, rq *connect.Request[apiv1.TenantServiceInviteGetRequest]) (*connect.Response[apiv1.TenantServiceInviteGetResponse], error) {
	var (
		req = rq.Msg
	)

	inv, err := u.inviteStore.GetInvite(ctx, req.Secret)
	if err != nil {
		if errors.Is(err, invite.ErrInviteNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the given invitation does not exist anymore"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TenantServiceInviteGetResponse{Invite: inv}), nil
}

func (u *tenantServiceServer) InvitesList(ctx context.Context, rq *connect.Request[apiv1.TenantServiceInvitesListRequest]) (*connect.Response[apiv1.TenantServiceInvitesListResponse], error) {
	var (
		req = rq.Msg
	)
	invites, err := u.inviteStore.ListInvites(ctx, req.Login)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TenantServiceInvitesListResponse{Invites: invites}), nil
}

func (u *tenantServiceServer) RemoveMember(ctx context.Context, rq *connect.Request[apiv1.TenantServiceRemoveMemberRequest]) (*connect.Response[apiv1.TenantServiceRemoveMemberResponse], error) {
	var (
		req = rq.Msg
	)

	membership, err := tutil.GetTenantMember(ctx, u.masterClient, req.Login, req.MemberId)
	if err != nil {
		return nil, err
	}

	if membership.MemberId == membership.TenantId {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot remove a member from their own default tenant"))
	}

	lastOwner, err := u.checkIfMemberIsLastOwner(ctx, membership)
	if err != nil {
		return nil, err
	}
	if lastOwner {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot remove last owner of a tenant"))
	}

	_, err = u.masterClient.TenantMember().Delete(ctx, &mdcv1.TenantMemberDeleteRequest{
		Id: membership.Meta.Id,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TenantServiceRemoveMemberResponse{}), nil
}

func (u *tenantServiceServer) UpdateMember(ctx context.Context, rq *connect.Request[apiv1.TenantServiceUpdateMemberRequest]) (*connect.Response[apiv1.TenantServiceUpdateMemberResponse], error) {
	var (
		req = rq.Msg
	)

	membership, err := tutil.GetTenantMember(ctx, u.masterClient, req.Login, req.MemberId)
	if err != nil {
		return nil, err
	}

	if membership.MemberId == membership.TenantId && req.Role != apiv1.TenantRole_TENANT_ROLE_OWNER {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot demote a user's role within their own default tenant"))
	}

	lastOwner, err := u.checkIfMemberIsLastOwner(ctx, membership)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if lastOwner && req.Role != apiv1.TenantRole_TENANT_ROLE_OWNER {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot demote last owner's permissions"))
	}

	if req.Role != apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED {
		// TODO: currently the API defines that only owners can update members so there is no possibility to elevate permissions
		// probably, we should still check that no elevation of permissions is possible in case we later change the API

		membership.Meta.Annotations[tutil.TenantRoleAnnotation] = req.Role.String()
	}

	updatedMember, err := u.masterClient.TenantMember().Update(ctx, &mdcv1.TenantMemberUpdateRequest{TenantMember: membership})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.TenantServiceUpdateMemberResponse{TenantMember: &apiv1.TenantMember{
		Id:        req.MemberId,
		Role:      req.Role,
		CreatedAt: updatedMember.TenantMember.Meta.CreatedTime,
	}}), nil
}

func (u *tenantServiceServer) checkIfMemberIsLastOwner(ctx context.Context, membership *mdcv1.TenantMember) (bool, error) {
	isOwner := tutil.TenantRoleFromMap(membership.Meta.Annotations) == apiv1.TenantRole_TENANT_ROLE_OWNER
	if !isOwner {
		return false, nil
	}

	resp, err := u.masterClient.TenantMember().Find(ctx, &mdcv1.TenantMemberFindRequest{
		TenantId: &membership.TenantId,
		Annotations: map[string]string{
			tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
		},
	})
	if err != nil {
		return false, err
	}

	return len(resp.TenantMembers) < 2, nil
}
