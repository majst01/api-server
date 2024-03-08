package project

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	v1 "github.com/metal-stack/masterdata-api/api/v1"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	DefaultProjectAnnotation = "metal-stack.io/default-project"
	ProjectRoleAnnotation    = "metalstack.cloud/project-role"
)

type Config struct {
	Log          *slog.Logger
	MasterClient mdc.Client
	InviteStore  InviteStore
}
type projectServiceServer struct {
	log          *slog.Logger
	masterClient mdc.Client
	inviteStore  InviteStore
}

func New(c Config) apiv1connect.ProjectServiceHandler {
	return &projectServiceServer{
		log:          c.Log.WithGroup("projectService"),
		masterClient: c.MasterClient,
		inviteStore:  c.InviteStore,
	}
}

// Get implements apiv1connect.ProjectServiceHandler.
func (p *projectServiceServer) Get(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceGetRequest]) (*connect.Response[apiv1.ProjectServiceGetResponse], error) {
	req := rq.Msg
	resp, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{Id: req.Project})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	result, err := toProject(resp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	pmlr, err := p.masterClient.ProjectMember().Find(ctx, &v1.ProjectMemberFindRequest{
		ProjectId: &req.Project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to list project members: %w", err))
	}

	result.ProjectMembers = append(result.ProjectMembers, &apiv1.ProjectMember{
		Id:        result.Tenant,
		Role:      apiv1.ProjectRole_PROJECT_ROLE_OWNER,
		CreatedAt: result.CreatedAt,
	})

	for _, pm := range pmlr.GetProjectMembers() {
		role := pm.Meta.Annotations[ProjectRoleAnnotation]

		result.ProjectMembers = append(result.ProjectMembers, &apiv1.ProjectMember{
			Id:        pm.TenantId,
			Role:      apiv1.ProjectRole(apiv1.ProjectRole_value[role]),
			CreatedAt: pm.Meta.CreatedTime,
		})
	}

	return connect.NewResponse(&apiv1.ProjectServiceGetResponse{Project: result}), nil
}

// List implements apiv1connect.ProjectServiceHandler.
func (p *projectServiceServer) List(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceListRequest]) (*connect.Response[apiv1.ProjectServiceListResponse], error) {
	claims, ok := token.TokenClaimsFromContext(ctx)
	if !ok || claims == nil {
		return connect.NewResponse(&apiv1.ProjectServiceListResponse{}), nil
	}

	var (
		req     = rq.Msg
		result  []*apiv1.Project
		findReq = &v1.ProjectFindRequest{}
	)

	if req.Name != nil {
		findReq.Name = wrapperspb.String(*req.Name)
	}
	if req.Tenant != nil {
		findReq.TenantId = wrapperspb.String(*req.Tenant)
	}

	resp, err := p.masterClient.Project().Find(ctx, findReq)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error retrieving projects from backend: %w", err))
	}

	if token.IsAdminToken(claims) {
		for _, project := range resp.GetProjects() {
			mdmProject := project

			p, err := toProject(mdmProject)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}

			result = append(result, p)
		}

		return connect.NewResponse(&apiv1.ProjectServiceListResponse{Projects: result}), nil
	}

	var (
		projectsByID      = projectsByID(resp.GetProjects())
		allowedProjectIDs []string
	)

	for subject := range claims.Permissions {
		if token.IsProjectSubject(subject) {
			allowedProjectIDs = append(allowedProjectIDs, subject)
		}
	}

	for subject := range claims.Roles {
		if token.IsProjectSubject(subject) {
			allowedProjectIDs = append(allowedProjectIDs, subject)
		}
	}

	for _, projectID := range allowedProjectIDs {
		project, ok := projectsByID[projectID]
		if !ok {
			continue
		}

		p, err := toProject(project)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		result = append(result, p)
	}

	return connect.NewResponse(&apiv1.ProjectServiceListResponse{Projects: result}), nil
}

// Create implements apiv1connect.ProjectServiceHandler.
func (p *projectServiceServer) Create(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceCreateRequest]) (*connect.Response[apiv1.ProjectServiceCreateResponse], error) {
	var (
		req = rq.Msg
	)

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

	project, err := toProject(createResp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// TODO: a user does not have the permissions to access this project after this, they need to re-login
	// possible solution: if we move the permissions into redis, we could inject it here immediately and the token
	// does not need to be re-issued (in general this approach has advantages like removal of permissions for a specific person)
	//
	// other workaround: return a new token with this response

	return connect.NewResponse(&apiv1.ProjectServiceCreateResponse{Project: project}), nil
}

// Delete implements apiv1connect.ProjectServiceHandler.
func (p *projectServiceServer) Delete(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceDeleteRequest]) (*connect.Response[apiv1.ProjectServiceDeleteResponse], error) {
	var (
		req = rq.Msg
	)

	getResp, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{
		Id: req.Project,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no project found with id %q: %w", req.Project, err))
	}

	if IsDefaultProject(getResp.Project) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the default-project cannot be deleted"))
	}

	result, err := toProject(getResp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceDeleteResponse{Project: result}), nil
}

// Update implements apiv1connect.ProjectServiceHandler.
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

	if IsDefaultProject(project) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the default-project cannot be updated"))
	}

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

	result, err := toProject(updatedResp.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceUpdateResponse{Project: result}), nil
}

// RemoveMember implements apiv1connect.ProjectServiceHandler.
func (p *projectServiceServer) RemoveMember(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceRemoveMemberRequest]) (*connect.Response[apiv1.ProjectServiceRemoveMemberResponse], error) {
	var (
		req = rq.Msg
	)

	membership, err := p.getInvitedProjectMember(ctx, req.Project, req.MemberId)
	if err != nil {
		return nil, err
	}

	_, err = p.masterClient.ProjectMember().Delete(ctx, &v1.ProjectMemberDeleteRequest{
		Id: membership.Meta.Id,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&apiv1.ProjectServiceRemoveMemberResponse{}), nil
}

// UpdateMember implements apiv1connect.ProjectServiceHandler.
func (p *projectServiceServer) UpdateMember(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceUpdateMemberRequest]) (*connect.Response[apiv1.ProjectServiceUpdateMemberResponse], error) {
	var (
		req = rq.Msg
	)

	membership, err := p.getInvitedProjectMember(ctx, req.Project, req.MemberId)
	if err != nil {
		return nil, err
	}

	if req.Role != apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED {
		// TODO: currently the API defines that only owners can update members so there is no possibility to elevate permissions
		// probably, we should still check that no elevation of permissions is possible in case we later change the API

		membership.Meta.Annotations[ProjectRoleAnnotation] = req.Role.String()
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

// InviteGet implements apiv1connect.ProjectServiceHandler.
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

// Invite implements apiv1connect.ProjectServiceHandler.
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

	var (
		secret    = generateInviteSecret()
		expiresAt = time.Now().Add(7 * 24 * time.Hour)
	)

	if req.Role == apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED {
		return nil, fmt.Errorf("project role must be specified")
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

// InviteAccept implements apiv1connect.ProjectServiceHandler.
func (p *projectServiceServer) InviteAccept(ctx context.Context, rq *connect.Request[apiv1.ProjectServiceInviteAcceptRequest]) (*connect.Response[apiv1.ProjectServiceInviteAcceptResponse], error) {
	claims, ok := token.TokenClaimsFromContext(ctx)
	if !ok || claims == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no claims found in request"))
	}
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

	tgr, err := p.masterClient.Tenant().Get(ctx, &v1.TenantGetRequest{
		Id: claims.Subject,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no account:%q found %w", claims.Subject, err))
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

	project, err := toProject(pgr.Project)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	memberships, err := p.masterClient.ProjectMember().Find(ctx, &v1.ProjectMemberFindRequest{
		ProjectId: &project.Uuid,
		TenantId:  &invitee.Meta.Id,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if len(memberships.GetProjectMembers()) > 0 {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("%s is already member of project %s", invitee.Meta.Id, project.Uuid))
	}

	err = p.inviteStore.DeleteInvite(ctx, invite)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	_, err = p.masterClient.ProjectMember().Create(ctx, &v1.ProjectMemberCreateRequest{
		ProjectMember: &v1.ProjectMember{
			Meta: &v1.Meta{
				Annotations: map[string]string{
					ProjectRoleAnnotation: invite.Role.String(),
				},
			},
			ProjectId: project.Uuid,
			TenantId:  invitee.Meta.Id,
		},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to store project member: %w", err))
	}

	return connect.NewResponse(&apiv1.ProjectServiceInviteAcceptResponse{Project: project.Uuid, ProjectName: project.Name}), nil
}

// InviteDelete implements apiv1connect.ProjectServiceHandler.
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

// InvitesList implements apiv1connect.ProjectServiceHandler.
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

func (p *projectServiceServer) getInvitedProjectMember(ctx context.Context, projectID, tenantID string) (*v1.ProjectMember, error) {
	getResp, err := p.masterClient.Project().Get(ctx, &v1.ProjectGetRequest{
		Id: projectID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no project found with id %q: %w", projectID, err))
	}

	if getResp.Project.TenantId == tenantID {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("original owner of the project cannot be modified"))
	}

	memberships, err := p.masterClient.ProjectMember().Find(ctx, &v1.ProjectMemberFindRequest{
		ProjectId: &projectID,
		TenantId:  &tenantID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	switch len(memberships.ProjectMembers) {
	case 0:
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("tenant %s is not a member of project %s", tenantID, projectID))
	case 1:
		// fallthrough
	default:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("found multiple membership associations for a member to a project"))
	}

	return memberships.GetProjectMembers()[0], nil
}

func toProject(p *v1.Project) (*apiv1.Project, error) {
	if p.Meta == nil {
		return nil, fmt.Errorf("project meta is nil")
	}
	return &apiv1.Project{
		Uuid:        p.Meta.Id,
		Name:        p.Name,
		Description: p.Description,
		Tenant:      p.TenantId,
		CreatedAt:   p.Meta.CreatedTime,
		UpdatedAt:   p.Meta.UpdatedTime,
	}, nil
}

func projectsByID(projects []*v1.Project) map[string]*v1.Project {
	result := map[string]*v1.Project{}

	for _, p := range projects {
		p := p

		if p.Meta == nil {
			continue
		}

		result[p.GetMeta().GetId()] = p
	}

	return result
}

func IsDefaultProject(p *v1.Project) bool {
	value, ok := p.Meta.Annotations[DefaultProjectAnnotation]
	if !ok {
		return false
	}

	res, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}

	return res
}
