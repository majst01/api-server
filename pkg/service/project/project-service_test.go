package project

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	putil "github.com/metal-stack/api-server/pkg/project"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	v1 "github.com/metal-stack/masterdata-api/api/v1"
	mdmv1mock "github.com/metal-stack/masterdata-api/api/v1/mocks"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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
				mock.On("Get", tmock.Anything, &v1.ProjectGetRequest{Id: "project"}).Return(&v1.ProjectResponse{
					Project: &v1.Project{
						Meta:     &v1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &v1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&v1.ListTenantMembersResponse{
					Tenants: []*v1.TenantWithMembershipAnnotations{
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "me"},
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
				mock.On("Find", tmock.Anything, &v1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&v1.ProjectMemberListResponse{
					ProjectMembers: []*v1.ProjectMember{
						{
							Meta: &v1.Meta{
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
					Uuid:   "project",
					Tenant: "me",
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
				mock.On("Get", tmock.Anything, &v1.ProjectGetRequest{Id: "project"}).Return(&v1.ProjectResponse{
					Project: &v1.Project{
						Meta:     &v1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &v1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&v1.ListTenantMembersResponse{
					Tenants: []*v1.TenantWithMembershipAnnotations{
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "guest"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_GUEST.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &v1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&v1.ProjectMemberListResponse{
					ProjectMembers: []*v1.ProjectMember{
						{
							Meta: &v1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &v1.Meta{
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
					Uuid:   "project",
					Tenant: "me",
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
				mock.On("Get", tmock.Anything, &v1.ProjectGetRequest{Id: "project"}).Return(&v1.ProjectResponse{
					Project: &v1.Project{
						Meta:     &v1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &v1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&v1.ListTenantMembersResponse{
					Tenants: []*v1.TenantWithMembershipAnnotations{
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "editor"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_VIEWER.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &v1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&v1.ProjectMemberListResponse{
					ProjectMembers: []*v1.ProjectMember{
						{
							Meta: &v1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &v1.Meta{
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
					Uuid:   "project",
					Tenant: "me",
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
				mock.On("Get", tmock.Anything, &v1.ProjectGetRequest{Id: "project"}).Return(&v1.ProjectResponse{
					Project: &v1.Project{
						Meta:     &v1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &v1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&v1.ListTenantMembersResponse{
					Tenants: []*v1.TenantWithMembershipAnnotations{
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "owner"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &v1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&v1.ProjectMemberListResponse{
					ProjectMembers: []*v1.ProjectMember{
						{
							Meta: &v1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &v1.Meta{
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
					Uuid:   "project",
					Tenant: "me",
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
				mock.On("Get", tmock.Anything, &v1.ProjectGetRequest{Id: "project"}).Return(&v1.ProjectResponse{
					Project: &v1.Project{
						Meta:     &v1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("ListTenantMembers", tmock.Anything, &v1.ListTenantMembersRequest{
					TenantId: "me", IncludeInherited: pointer.Pointer(true),
				}).Return(&v1.ListTenantMembersResponse{
					Tenants: []*v1.TenantWithMembershipAnnotations{
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &v1.Tenant{
								Meta: &v1.Meta{Id: "viewer"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.TenantRole_TENANT_ROLE_VIEWER.String(),
							},
						},
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &v1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&v1.ProjectMemberListResponse{
					ProjectMembers: []*v1.ProjectMember{
						{
							Meta: &v1.Meta{
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
					Uuid:   "project",
					Tenant: "me",
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
				mock.On("Get", tmock.Anything, &v1.ProjectGetRequest{Id: "project"}).Return(&v1.ProjectResponse{
					Project: &v1.Project{
						Meta:     &v1.Meta{Id: "project"},
						TenantId: "me",
					},
				}, nil)
			},
			projectMemberServiceMock: func(mock *tmock.Mock) {
				mock.On("Find", tmock.Anything, &v1.ProjectMemberFindRequest{
					ProjectId: pointer.Pointer("project"),
				}).Return(&v1.ProjectMemberListResponse{
					ProjectMembers: []*v1.ProjectMember{
						{
							Meta: &v1.Meta{
								Annotations: map[string]string{
									putil.ProjectRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
								},
							},
							ProjectId: "project",
							TenantId:  "me",
						},
						{
							Meta: &v1.Meta{
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
					Uuid:   "project",
					Tenant: "me",
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
