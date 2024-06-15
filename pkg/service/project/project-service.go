package project

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/metal-stack/api-server/pkg/invite"
	putil "github.com/metal-stack/api-server/pkg/project"
	"github.com/metal-stack/api-server/pkg/service/user"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	v1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	metalgo "github.com/metal-stack/metal-go"
	"github.com/metal-stack/metal-go/api/client/ip"
	"github.com/metal-stack/metal-go/api/client/project"
	"github.com/metal-stack/metal-go/api/models"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Config struct {
	Log          *slog.Logger
	MasterClient mdc.Client
	MetalClient  metalgo.Client
	InviteStore  invite.ProjectInviteStore
	TokenStore   token.TokenStore
}
type projectServiceServer struct {
	log          *slog.Logger
	masterClient mdc.Client
	metalClient  metalgo.Client
	inviteStore  invite.ProjectInviteStore
	tokenStore   token.TokenStore
}

func New(c Config) apiv1connect.ProjectServiceHandler {
	return &projectServiceServer{
		log:          c.Log.WithGroup("projectService"),
		masterClient: c.MasterClient,
		metalClient:  c.MetalClient,
		inviteStore:  c.InviteStore,
		tokenStore:   c.TokenStore,
	}
}

func (p *projectServiceServer) Get(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceGetRequest]) (*connect.Response[apiv1.ProjectServiceGetResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)
	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	resp, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{Id: req.Project})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	project, err := putil.ToProject(resp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	pmlr, err := p.masterClient.ProjectMember().Find(ctx, &v1.ProjectMemberFindRequest{
		ProjectId: &req.Project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to list project members: %w", err))
	}

	memberMap := map[string]*apiv1.ProjectMember{}

	for _, pm := range pmlr.GetProjectMembers() {
		memberMap[pm.TenantId] = &apiv1.ProjectMember{
			Id:        pm.TenantId,
			Role:      putil.ProjectRoleFromMap(pm.Meta.Annotations),
			CreatedAt: pm.Meta.CreatedTime,
		}
	}

	role := t.TenantRoles[project.Tenant]

	includeInheritedMembers := false
	if role != apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED && role < apiv1.TenantRole_TENANT_ROLE_GUEST {
		includeInheritedMembers = true
	}
	if t.AdminRole != nil {
		includeInheritedMembers = true
	}

	if includeInheritedMembers {
		// we are at least viewer for this tenant, we should also be able to see all indirect members of this project

		tmlr, err := p.masterClient.Tenant().ListTenantMembers(ctx, &v1.ListTenantMembersRequest{TenantId: project.Tenant, IncludeInherited: pointer.Pointer(true)})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to list project members: %w", err))
		}

		for _, tm := range tmlr.GetTenants() {
			var projectRole apiv1.ProjectRole
			switch tutil.TenantRoleFromMap(tm.TenantAnnotations) {
			case apiv1.TenantRole_TENANT_ROLE_OWNER:
				projectRole = apiv1.ProjectRole_PROJECT_ROLE_OWNER
			case apiv1.TenantRole_TENANT_ROLE_EDITOR:
				projectRole = apiv1.ProjectRole_PROJECT_ROLE_EDITOR
			case apiv1.TenantRole_TENANT_ROLE_VIEWER:
				projectRole = apiv1.ProjectRole_PROJECT_ROLE_VIEWER
			case apiv1.TenantRole_TENANT_ROLE_GUEST, apiv1.TenantRole_TENANT_ROLE_UNSPECIFIED:
				continue
			default:
				continue
			}

			member, ok := memberMap[tm.Tenant.Meta.Id]
			if !ok {
				memberMap[tm.Tenant.Meta.Id] = &apiv1.ProjectMember{
					Id:                  tm.Tenant.Meta.Id,
					Role:                projectRole,
					CreatedAt:           tm.Tenant.Meta.CreatedTime,
					InheritedMembership: true,
				}

				continue
			}

			if member.Role > projectRole {
				member.Role = projectRole
				memberMap[tm.Tenant.Meta.Id] = member
			}
		}
	}

	var projectMembers []*apiv1.ProjectMember
	for _, m := range memberMap {
		projectMembers = append(projectMembers, m)
	}

	sort.Slice(projectMembers, func(i, j int) bool {
		return projectMembers[i].Id < projectMembers[j].Id
	})

	return connect.NewResponse(&apiv1.ProjectServiceGetResponse{Project: project, ProjectMembers: projectMembers}), nil
}

func (p *projectServiceServer) List(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceListRequest]) (*connect.Response[apiv1.ProjectServiceListResponse], error) {
	token, ok := token.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	var (
		req    = rq.Msg
		result []*apiv1.Project
	)

	pat, err := user.GetProjectsAndTenants(ctx, p.masterClient, token.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error retrieving projects from backend: %w", err))
	}

	for _, project := range pat.Projects {
		// TODO: maybe we can pass the filter and not filter here

		if req.Name != nil && project.Name != *req.Name {
			continue
		}
		if req.Tenant != nil && project.Tenant != *req.Tenant {
			continue
		}

		result = append(result, project)
	}

	return connect.NewResponse(&apiv1.ProjectServiceListResponse{Projects: result}), nil
}

func (p *projectServiceServer) Create(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceCreateRequest]) (*connect.Response[apiv1.ProjectServiceCreateResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)

	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	findResp, err := p.masterClient.Project().Find(ctx, &v1.ProjectFindRequest{
		Name:     wrapperspb.String(req.Name),
		TenantId: wrapperspb.String(req.Login),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error retrieving projects from backend: %w", err))
	}

	if len(findResp.Projects) > 0 {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("a project with name %q already exists for this organization", req.Name))
	}

	createResp, err := p.masterClient.Project().Create(ctx, &v1.ProjectCreateRequest{
		Project: &v1.Project{
			Meta: &v1.Meta{
				Id: uuid.NewString(),
			},
			Name:        req.Name,
			Description: req.Description,
			TenantId:    req.Login,
		},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error creating project: %w", err))
	}

	project, err := putil.ToProject(createResp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	_, err = p.masterClient.ProjectMember().Create(ctx, &v1.ProjectMemberCreateRequest{
		ProjectMember: &v1.ProjectMember{
			Meta: &v1.Meta{
				Annotations: map[string]string{
					putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
				},
			},
			ProjectId: project.Uuid,
			TenantId:  t.UserId,
		},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to store project member: %w", err))
	}

	// inject new project into token roles to give immediate access to the project with the accessing token
	if t.ProjectRoles == nil {
		t.ProjectRoles = map[string]apiv1.ProjectRole{}
	}
	t.ProjectRoles[project.Uuid] = apiv1.ProjectRole_PROJECT_ROLE_OWNER

	err = p.tokenStore.Set(ctx, t)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("project was created but error when injecting role into current session token, re-issue token to receive access to the project: %w", err))
	}

	return connect.NewResponse(&apiv1.ProjectServiceCreateResponse{Project: project}), nil
}

func (p *projectServiceServer) Delete(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceDeleteRequest]) (*connect.Response[apiv1.ProjectServiceDeleteResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)

	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	getResp, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{
		Id: req.Project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no project found with id %q: %w", req.Project, err))
	}

	if t.AdminRole != nil && *t.AdminRole == apiv1.AdminRole_ADMIN_ROLE_EDITOR {
		// we allow deleting default-projects with admins explicitly in order to allow an admin to fully delete a tenant on demand
	} else {
		if putil.IsDefaultProject(getResp.Project) {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the default-project cannot be deleted"))
		}
	}

	ips, err := p.metalClient.IP().FindIPs(ip.NewFindIPsParams().WithBody(&models.V1IPFindRequest{
		Projectid: req.Project,
	}).WithContext(ctx), nil)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error retrieving ips: %w", err))
	}

	if len(ips.Payload) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("there are still ips associated with this project, you need to delete them first"))
	}

	_, err = p.metalClient.Project().DeleteProject(project.NewDeleteProjectParams().WithID(req.Project).WithContext(ctx), nil)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error updating project: %w", err))
	}

	// TODO: ensure project tokens are revoked / cleaned up

	result, err := putil.ToProject(getResp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceDeleteResponse{Project: result}), nil
}

func (p *projectServiceServer) Update(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceUpdateRequest]) (*connect.Response[apiv1.ProjectServiceUpdateResponse], error) {
	var (
		req = rq.Msg
	)

	getResp, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{
		Id: req.Project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no project found with id %q: %w", req.Project, err))
	}

	project := getResp.Project

	if req.Name != nil {
		project.Name = *req.Name
	}

	if req.Description != nil {
		project.Description = *req.Description
	}

	updatedResp, err := p.masterClient.Project().Update(ctx, &v1.ProjectUpdateRequest{
		Project: project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error updating project: %w", err))
	}

	result, err := putil.ToProject(updatedResp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceUpdateResponse{Project: result}), nil
}

func (p *projectServiceServer) RemoveMember(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceRemoveMemberRequest]) (*connect.Response[apiv1.ProjectServiceRemoveMemberResponse], error) {
	var (
		req   = rq.Msg
		t, ok = token.TokenFromContext(ctx)
	)

	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	membership, project, err := putil.GetProjectMember(ctx, p.masterClient, req.Project, req.MemberId)
	if err != nil {
		return nil, err
	}

	if putil.IsDefaultProject(project) && project.TenantId == req.MemberId {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot remove a user from their own default project"))
	}

	lastOwner, err := p.checkIfMemberIsLastOwner(ctx, membership)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if lastOwner {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot remove last owner of a project"))
	}

	_, err = p.masterClient.ProjectMember().Delete(ctx, &v1.ProjectMemberDeleteRequest{
		Id: membership.Meta.Id,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceRemoveMemberResponse{}), nil
}

func (p *projectServiceServer) UpdateMember(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceUpdateMemberRequest]) (*connect.Response[apiv1.ProjectServiceUpdateMemberResponse], error) {
	var (
		req = rq.Msg
	)

	membership, project, err := putil.GetProjectMember(ctx, p.masterClient, req.Project, req.MemberId)
	if err != nil {
		return nil, err
	}

	if putil.IsDefaultProject(project) && project.TenantId == req.MemberId && req.Role != apiv1.ProjectRole_PROJECT_ROLE_OWNER {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot demote a user's role within their default project"))
	}

	if req.Role != apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED {
		// TODO: currently the API defines that only owners can update members so there is no possibility to elevate permissions
		// probably, we should still check that no elevation of permissions is possible in case we later change the API

		membership.Meta.Annotations[putil.ProjectRoleAnnotation] = req.Role.String()
	}

	lastOwner, err := p.checkIfMemberIsLastOwner(ctx, membership)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if lastOwner && req.Role != apiv1.ProjectRole_PROJECT_ROLE_OWNER {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("cannot demote last owner's permissions"))
	}

	updatedMember, err := p.masterClient.ProjectMember().Update(ctx, &v1.ProjectMemberUpdateRequest{ProjectMember: membership})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceUpdateMemberResponse{ProjectMember: &apiv1.ProjectMember{
		Id:        req.MemberId,
		Role:      req.Role,
		CreatedAt: updatedMember.ProjectMember.Meta.CreatedTime,
	}}), nil
}

func (p *projectServiceServer) InviteGet(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceInviteGetRequest]) (*connect.Response[apiv1.ProjectServiceInviteGetResponse], error) {
	var (
		req = rq.Msg
	)

	invite, err := p.inviteStore.GetInvite(ctx, req.Secret)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the given invitation does not exist anymore"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceInviteGetResponse{Invite: invite}), nil
}

func (p *projectServiceServer) Invite(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceInviteRequest]) (*connect.Response[apiv1.ProjectServiceInviteResponse], error) {
	var (
		req = rq.Msg
	)
	pgr, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{
		Id: req.Project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no project found with id %q: %w", req.Project, err))
	}

	tgr, err := p.masterClient.Tenant().Get(ctx, &v1.TenantGetRequest{
		Id: pgr.Project.TenantId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no account:%q found %w", pgr.Project.TenantId, err))
	}

	secret, err := invite.GenerateInviteSecret()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	var (
		expiresAt = time.Now().Add(7 * 24 * time.Hour)
	)

	if req.Role == apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("project role must be specified"))
	}

	invite := &apiv1.ProjectInvite{
		Secret:      secret,
		Project:     pgr.Project.Meta.Id,
		Role:        req.Role,
		Joined:      false,
		ProjectName: pgr.Project.Name,
		Tenant:      pgr.Project.TenantId,
		TenantName:  tgr.Tenant.Name,
		ExpiresAt:   timestamppb.New(expiresAt),
		JoinedAt:    &timestamppb.Timestamp{},
	}
	p.log.Info("project invitation created", "invitation", invite)

	err = p.inviteStore.SetInvite(ctx, invite)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceInviteResponse{Invite: invite}), nil
}

func (p *projectServiceServer) InviteAccept(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceInviteAcceptRequest]) (*connect.Response[apiv1.ProjectServiceInviteAcceptResponse], error) {
	var (
		t, ok = token.TokenFromContext(ctx)
		req   = rq.Msg
	)

	if !ok || t == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	invite, err := p.inviteStore.GetInvite(ctx, req.Secret)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the given invitation does not exist anymore"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tgr, err := p.masterClient.Tenant().Get(ctx, &v1.TenantGetRequest{
		Id: t.UserId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no account:%q found %w", t.UserId, err))
	}

	invitee := tgr.Tenant

	pgr, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{
		Id: invite.Project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no project:%q for invite not found %w", invite.Project, err))
	}

	if pgr.Project.TenantId == invitee.Meta.Id {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("an owner cannot accept invitations to own projects"))
	}

	memberships, err := p.masterClient.ProjectMember().Find(ctx, &v1.ProjectMemberFindRequest{
		ProjectId: &invite.Project,
		TenantId:  &invitee.Meta.Id,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if len(memberships.GetProjectMembers()) > 0 {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("%s is already member of project %s", invitee.Meta.Id, invite.Project))
	}

	err = p.inviteStore.DeleteInvite(ctx, invite)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	_, err = p.masterClient.ProjectMember().Create(ctx, &v1.ProjectMemberCreateRequest{
		ProjectMember: &v1.ProjectMember{
			Meta: &v1.Meta{
				Annotations: map[string]string{
					putil.ProjectRoleAnnotation: invite.Role.String(),
				},
			},
			ProjectId: invite.Project,
			TenantId:  invitee.Meta.Id,
		},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to store project member: %w", err))
	}

	return connect.NewResponse(&apiv1.ProjectServiceInviteAcceptResponse{Project: invite.Project, ProjectName: invite.ProjectName}), nil
}

func (p *projectServiceServer) InviteDelete(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceInviteDeleteRequest]) (*connect.Response[apiv1.ProjectServiceInviteDeleteResponse], error) {
	var (
		req = rq.Msg
	)

	err := p.inviteStore.DeleteInvite(ctx, &apiv1.ProjectInvite{Secret: req.Secret, Project: req.Project})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceInviteDeleteResponse{}), nil
}

func (p *projectServiceServer) InvitesList(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceInvitesListRequest]) (*connect.Response[apiv1.ProjectServiceInvitesListResponse], error) {
	var (
		req = rq.Msg
	)
	invites, err := p.inviteStore.ListInvites(ctx, req.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceInvitesListResponse{Invites: invites}), nil
}

func (p *projectServiceServer) checkIfMemberIsLastOwner(ctx context.Context, membership *v1.ProjectMember) (bool, error) {
	isOwner := membership.Meta.Annotations[putil.ProjectRoleAnnotation] == apiv1.ProjectRole_PROJECT_ROLE_OWNER.String()
	if !isOwner {
		return false, nil
	}

	resp, err := p.masterClient.ProjectMember().Find(ctx, &v1.ProjectMemberFindRequest{
		ProjectId: &membership.ProjectId,
		Annotations: map[string]string{
			putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
		},
	})
	if err != nil {
		return false, err
	}

	return len(resp.ProjectMembers) < 2, nil
}
