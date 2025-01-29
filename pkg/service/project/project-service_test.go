package project

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/metal-stack/api-server/pkg/invite"
	putil "github.com/metal-stack/api-server/pkg/project"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/metalstack/api/v1"
	mdmv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdmv1mock "github.com/metal-stack/masterdata-api/api/v1/mocks"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func newMasterdataMockClient(
	t *testing.T,
	tenantServiceMock func(mock *tmock.Mock),
	tenantMemberServiceMock func(mock *tmock.Mock),
	projectServiceMock func(mock *tmock.Mock),
	projectMemberServiceMock func(mock *tmock.Mock),
) *mdc.MockClient {
	tsc := mdmv1mock.NewTenantServiceClient(t)
	if tenantServiceMock != nil {
		tenantServiceMock(&tsc.Mock)
	}
	psc := mdmv1mock.NewProjectServiceClient(t)
	if projectServiceMock != nil {
		projectServiceMock(&psc.Mock)
	}
	pmsc := mdmv1mock.NewProjectMemberServiceClient(t)
	if projectMemberServiceMock != nil {
		projectMemberServiceMock(&pmsc.Mock)
	}
	tmsc := mdmv1mock.NewTenantMemberServiceClient(t)
	if tenantMemberServiceMock != nil {
		tenantMemberServiceMock(&tmsc.Mock)
	}

	return mdc.NewMock(psc, tsc, pmsc, tmsc)
}

func Test_projectServiceServer_Get(t *testing.T) {
	tests := []struct {
		name                     string
		req                      *apiv1.ProjectServiceGetRequest
		tenantRole               apiv1.TenantRole
		projectServiceMock       func(mock *tmock.Mock)
		tenantServiceMock        func(mock *tmock.Mock)
		projectMemberServiceMock func(mock *tmock.Mock)
		want                     *apiv1.ProjectServiceGetResponse
		wantErr                  bool
	}{
		{
			name: "no members except one",
			req: &apiv1.ProjectServiceGetRequest{
				Project: "project",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_OWNER,
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{Id: "project"}).Return(&mdmv1.ProjectResponse{
					Project: &mdmv1.Project{
						Meta:     &mdmv1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							ProjectAnnotations: map[string]string{
								putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &mdmv1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&mdmv1.ProjectMemberListResponse{
					ProjectMembers: []*mdmv1.ProjectMember{
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
					},
				}, nil)
			},
			want: &apiv1.ProjectServiceGetResponse{
				Project: &apiv1.Project{
					Uuid:      "project",
					Tenant:    "me",
					AvatarUrl: pointer.Pointer(""),
				},
				ProjectMembers: []*apiv1.ProjectMember{
					{
						Id:   "me",
						Role: apiv1.ProjectRole_PROJECT_ROLE_OWNER,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "one direct member with tenant role guest",
			req: &apiv1.ProjectServiceGetRequest{
				Project: "project",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_OWNER,
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{Id: "project"}).Return(&mdmv1.ProjectResponse{
					Project: &mdmv1.Project{
						Meta:     &mdmv1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "guest"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_GUEST.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &mdmv1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&mdmv1.ProjectMemberListResponse{
					ProjectMembers: []*mdmv1.ProjectMember{
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_VIEWER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "guest",
						},
					},
				}, nil)
			},
			want: &apiv1.ProjectServiceGetResponse{
				Project: &apiv1.Project{
					Uuid:      "project",
					Tenant:    "me",
					AvatarUrl: pointer.Pointer(""),
				},
				ProjectMembers: []*apiv1.ProjectMember{
					{
						Id:   "guest",
						Role: apiv1.ProjectRole_PROJECT_ROLE_VIEWER,
					},
					{
						Id:   "me",
						Role: apiv1.ProjectRole_PROJECT_ROLE_OWNER,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "editor member with tenant role viewer",
			req: &apiv1.ProjectServiceGetRequest{
				Project: "project",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_OWNER,
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{Id: "project"}).Return(&mdmv1.ProjectResponse{
					Project: &mdmv1.Project{
						Meta:     &mdmv1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "editor"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_VIEWER.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &mdmv1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&mdmv1.ProjectMemberListResponse{
					ProjectMembers: []*mdmv1.ProjectMember{
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_EDITOR.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "editor",
						},
					},
				}, nil)
			},
			want: &apiv1.ProjectServiceGetResponse{
				Project: &apiv1.Project{
					Uuid:      "project",
					Tenant:    "me",
					AvatarUrl: pointer.Pointer(""),
				},
				ProjectMembers: []*apiv1.ProjectMember{
					{
						Id:   "editor",
						Role: apiv1.ProjectRole_PROJECT_ROLE_EDITOR,
					},
					{
						Id:   "me",
						Role: apiv1.ProjectRole_PROJECT_ROLE_OWNER,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "viewer member with tenant role owner",
			req: &apiv1.ProjectServiceGetRequest{
				Project: "project",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_OWNER,
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{Id: "project"}).Return(&mdmv1.ProjectResponse{
					Project: &mdmv1.Project{
						Meta:     &mdmv1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "owner"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &mdmv1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&mdmv1.ProjectMemberListResponse{
					ProjectMembers: []*mdmv1.ProjectMember{
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_VIEWER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "owner",
						},
					},
				}, nil)
			},
			want: &apiv1.ProjectServiceGetResponse{
				Project: &apiv1.Project{
					Uuid:      "project",
					Tenant:    "me",
					AvatarUrl: pointer.Pointer(""),
				},
				ProjectMembers: []*apiv1.ProjectMember{
					{
						Id:   "me",
						Role: apiv1.ProjectRole_PROJECT_ROLE_OWNER,
					},
					{
						Id:   "owner",
						Role: apiv1.ProjectRole_PROJECT_ROLE_OWNER,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "inherited member",
			req: &apiv1.ProjectServiceGetRequest{
				Project: "project",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_VIEWER,
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{Id: "project"}).Return(&mdmv1.ProjectResponse{
					Project: &mdmv1.Project{
						Meta:     &mdmv1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "viewer"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_VIEWER.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &mdmv1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&mdmv1.ProjectMemberListResponse{
					ProjectMembers: []*mdmv1.ProjectMember{
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
					},
				}, nil)
			},
			want: &apiv1.ProjectServiceGetResponse{
				Project: &apiv1.Project{
					Uuid:      "project",
					Tenant:    "me",
					AvatarUrl: pointer.Pointer(""),
				},
				ProjectMembers: []*apiv1.ProjectMember{
					{
						Id:   "me",
						Role: apiv1.ProjectRole_PROJECT_ROLE_OWNER,
					},
					{
						Id:                  "viewer",
						Role:                apiv1.ProjectRole_PROJECT_ROLE_VIEWER,
						InheritedMembership: true,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "do not list inherited member for guests",
			req: &apiv1.ProjectServiceGetRequest{
				Project: "project",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_GUEST,
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{Id: "project"}).Return(&mdmv1.ProjectResponse{
					Project: &mdmv1.Project{
						Meta:     &mdmv1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &mdmv1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&mdmv1.ProjectMemberListResponse{
					ProjectMembers: []*mdmv1.ProjectMember{
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &mdmv1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_EDITOR.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "guest",
						},
					},
				}, nil)
			},
			want: &apiv1.ProjectServiceGetResponse{
				Project: &apiv1.Project{
					Uuid:      "project",
					Tenant:    "me",
					AvatarUrl: pointer.Pointer(""),
				},
				ProjectMembers: []*apiv1.ProjectMember{
					{
						Id:   "guest",
						Role: apiv1.ProjectRole_PROJECT_ROLE_EDITOR,
					},
					{
						Id:   "me",
						Role: apiv1.ProjectRole_PROJECT_ROLE_OWNER,
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			m := miniredis.RunT(t)
			defer m.Close()
			c := redis.NewClient(&redis.Options{Addr: m.Addr()})

			tokenStore := token.NewRedisStore(c)

			ctx := token.ContextWithToken(context.Background(), &apiv1.Token{
				TenantRoles: map[string]apiv1.TenantRole{
					tt.want.Project.Tenant: tt.tenantRole,
				},
			})

			p := &projectServiceServer{
				log:          slog.Default(),
				masterClient: newMasterdataMockClient(t, tt.tenantServiceMock, nil, tt.projectServiceMock, tt.projectMemberServiceMock),
				tokenStore:   tokenStore,
			}

			result, err := p.Get(ctx, connect.NewRequest(tt.req))
			require.NoError(t, err)
			assert.Equal(t, tt.want, result.Msg)
		})
	}
}

func Test_service_InviteAccept(t *testing.T) {
	ctx := context.Background()
	secret, err := invite.GenerateInviteSecret()
	require.NoError(t, err)

	tests := []struct {
		name                     string
		tenant                   *apiv1.ProjectServiceInviteAcceptRequest
		token                    *apiv1.Token
		projectServiceMock       func(mock *tmock.Mock)
		tenantServiceMock        func(mock *tmock.Mock)
		projectMemberServiceMock func(mock *tmock.Mock)
		inviteStorePrepare       func(store invite.ProjectInviteStore)
		want                     *apiv1.ProjectServiceInviteAcceptResponse
		wantErr                  *connect.Error
	}{
		{
			name: "accept an invite",
			tenant: &apiv1.ProjectServiceInviteAcceptRequest{
				Secret: secret,
			},
			token: &apiv1.Token{
				Uuid:   "123",
				UserId: "new-member",
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{Id: "new-member"}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{
					Meta: &mdmv1.Meta{Id: "new-member"},
				}}, nil)
			},
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{Id: "1"}).Return(&mdmv1.ProjectResponse{Project: &mdmv1.Project{
					Meta:     &mdmv1.Meta{Id: "1"},
					TenantId: "a",
				}}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &mdmv1.ProjectMemberFindRequest{TenantId: pointer.Pointer("new-member"), ProjectId: pointer.Pointer("1")}).Return(&mdmv1.ProjectMemberListResponse{ProjectMembers: nil}, nil)
				mock.On("Create", tmock.Anything, &mdmv1.ProjectMemberCreateRequest{
					ProjectMember: &mdmv1.ProjectMember{
						Meta: &mdmv1.Meta{
							Annotations: map[string]string{
								putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_EDITOR.String(),
							},
						},
						TenantId:  "new-member",
						ProjectId: "1",
					},
				}).Return(&mdmv1.ProjectMemberResponse{
					ProjectMember: &mdmv1.ProjectMember{
						Meta: &mdmv1.Meta{
							Id: "a-random-uuid",
						},
						TenantId:  "new-member",
						ProjectId: "1",
					},
				}, nil)
			},
			inviteStorePrepare: func(store invite.ProjectInviteStore) {
				err := store.SetInvite(ctx, &apiv1.ProjectInvite{
					Secret:      secret,
					Project:     "1",
					Role:        apiv1.ProjectRole_PROJECT_ROLE_EDITOR,
					Joined:      false,
					ProjectName: "name of 1",
					Tenant:      "user a",
					TenantName:  "name of user a",
					ExpiresAt:   timestamppb.New(time.Now().Add(10 * time.Minute)),
					JoinedAt:    nil,
				})
				require.NoError(t, err)
			},
			want: &apiv1.ProjectServiceInviteAcceptResponse{
				ProjectName: "name of 1",
				Project:     "1",
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := miniredis.RunT(t)
			defer m.Close()

			var (
				c = redis.NewClient(&redis.Options{Addr: m.Addr()})

				inviteStore = invite.NewProjectRedisStore(c)
			)

			ctx := token.ContextWithToken(ctx, tt.token)

			if tt.inviteStorePrepare != nil {
				tt.inviteStorePrepare(inviteStore)
			}

			p := &projectServiceServer{
				log:          slog.Default(),
				masterClient: newMasterdataMockClient(t, tt.tenantServiceMock, nil, tt.projectServiceMock, tt.projectMemberServiceMock),
				inviteStore:  inviteStore,
			}

			result, err := p.InviteAccept(ctx, connect.NewRequest(tt.tenant))
			require.NoError(t, err)

			assert.Equal(t, result.Msg.ProjectName, tt.want.ProjectName)
			assert.Equal(t, result.Msg.Project, tt.want.Project)
		})
	}
}
