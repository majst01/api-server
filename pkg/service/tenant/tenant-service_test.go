package tenant

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/go-cmp/cmp/cmpopts"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	mdmv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdmv1mock "github.com/metal-stack/masterdata-api/api/v1/mocks"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/pkg/testcommon"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/runtime/protoimpl"

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

func newMockedTenantServiceInterceptor(tenantServiceMock func(mock *mdmv1mock.TenantServiceClient), projectServiceMock func(mock *mdmv1mock.ProjectServiceClient)) *tenantInterceptor {
	tsc := &mdmv1mock.TenantServiceClient{}
	if tenantServiceMock != nil {
		tenantServiceMock(tsc)
	}
	psc := &mdmv1mock.ProjectServiceClient{}
	if projectServiceMock != nil {
		projectServiceMock(psc)
	}
	pmsc := &mdmv1mock.ProjectMemberServiceClient{}
	mc := mdc.NewMock(psc, tsc, pmsc, nil)
	return NewInterceptor(slog.Default(), mc)
}

func Test_service_Create(t *testing.T) {
	tests := []struct {
		name                    string
		tenant                  *apiv1.TenantServiceCreateRequest
		tenantServiceMock       func(mock *tmock.Mock)
		tenantMemberServiceMock func(mock *tmock.Mock)
		want                    *apiv1.TenantServiceCreateResponse
		wantErr                 *connect.Error
	}{
		{
			name: "create user",
			tenant: &apiv1.TenantServiceCreateRequest{
				Name:        "test",
				Description: pointer.Pointer("test tenant"),
				Email:       pointer.Pointer("foo@a.b"),
				AvatarUrl:   pointer.Pointer("https://example.jpg"),
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				matcher := testcommon.MatchByCmpDiff(t, &mdmv1.TenantCreateRequest{
					Tenant: &mdmv1.Tenant{
						Meta: &mdmv1.Meta{
							Annotations: map[string]string{
								"metal-stack.io/admitted":     "true",
								"metal-stack.io/avatarurl":    "https://example.jpg",
								"metal-stack.io/email":        "foo@a.b",
								"metal-stack.io/phone":        "1023",
								"metal-stack.io/emailconsent": "false",
								"metal-stack.io/onboarded":    "false",
								"metal-stack.io/creator":      "original-owner",
							},
						},
						Name:        "test",
						Description: "test tenant",
					},
				}, cmpopts.IgnoreTypes(protoimpl.MessageState{}))

				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{Id: "original-owner"}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{}}, nil)
				mock.On("Create", tmock.Anything, matcher).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{Meta: &mdmv1.Meta{Id: "e7938bfa-9e47-4fa4-af8c-c059f938f467"}, Name: "test"}}, nil)
			},
			tenantMemberServiceMock: func(mock *tmock.Mock) {
				member := &mdmv1.TenantMember{
					Meta: &mdmv1.Meta{
						Annotations: map[string]string{
							"metalstack.cloud/tenant-role": "TENANT_ROLE_OWNER",
						},
					},
					TenantId: "<generated-at-runtime>",
					MemberId: "original-owner",
				}
				matcher := testcommon.MatchByCmpDiff(t, &mdmv1.TenantMemberCreateRequest{
					TenantMember: member,
				}, cmpopts.IgnoreTypes(protoimpl.MessageState{}), cmpopts.IgnoreFields(mdmv1.TenantMember{}, "TenantId"))

				mock.On("Create", tmock.Anything, matcher).Return(&mdmv1.TenantMemberResponse{TenantMember: member}, nil)
			},
			want: &apiv1.TenantServiceCreateResponse{Tenant: &apiv1.Tenant{
				Login: "e7938bfa-9e47-4fa4-af8c-c059f938f467",
				Name:  "test",
			}},
			wantErr: nil,
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
				UserId: "original-owner",
			})

			s := &tenantServiceServer{
				log:          slog.Default(),
				masterClient: newMasterdataMockClient(t, tt.tenantServiceMock, tt.tenantMemberServiceMock, nil, nil),
				inviteStore:  nil,
				tokenStore:   tokenStore,
			}

			result, err := s.Create(ctx, connect.NewRequest(tt.tenant))
			require.NoError(t, err)
			assert.Equal(t, result.Msg.Tenant.Login, tt.want.Tenant.Login)
			assert.Equal(t, result.Msg.Tenant.Name, tt.want.Tenant.Name)
		})
	}
}

func Test_service_Get(t *testing.T) {
	tests := []struct {
		name                    string
		req                     *apiv1.TenantServiceGetRequest
		tenantRole              apiv1.TenantRole
		tenantServiceMock       func(mock *tmock.Mock)
		tenantMemberServiceMock func(mock *tmock.Mock)
		want                    *apiv1.TenantServiceGetResponse
		wantErr                 *connect.Error
	}{
		{
			name: "no members apart from self",
			req: &apiv1.TenantServiceGetRequest{
				Login: "me",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_OWNER,
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{Id: "me"}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{
					Meta: &mdmv1.Meta{Id: "me"},
				}}, nil)

				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{TenantId: "me"}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
							},
						},
					},
				}, nil)
			},
			want: &apiv1.TenantServiceGetResponse{Tenant: &apiv1.Tenant{
				Login: "me",
			},
				TenantMembers: []*apiv1.TenantMember{
					{
						Id:   "me",
						Role: 1,
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "one direct member",
			req: &apiv1.TenantServiceGetRequest{
				Login: "me",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_OWNER,
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{Id: "me"}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{
					Meta: &mdmv1.Meta{Id: "me"},
				}}, nil)

				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{TenantId: "me"}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "viewer"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_VIEWER.String(),
							},
						},
					},
				}, nil)
			},
			want: &apiv1.TenantServiceGetResponse{Tenant: &apiv1.Tenant{
				Login: "me",
			},
				TenantMembers: []*apiv1.TenantMember{
					{
						Id:   "me",
						Role: 1,
					},
					{
						Id:   "viewer",
						Role: 3,
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "one guest member",
			req: &apiv1.TenantServiceGetRequest{
				Login: "me",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_OWNER,
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{Id: "me"}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{
					Meta: &mdmv1.Meta{Id: "me"},
				}}, nil)

				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{TenantId: "me"}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "guest"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_UNSPECIFIED.String(),
							},
						},
					},
				}, nil)
			},
			want: &apiv1.TenantServiceGetResponse{Tenant: &apiv1.Tenant{
				Login: "me",
			},
				TenantMembers: []*apiv1.TenantMember{
					{
						Id:   "me",
						Role: 1,
					},
					{
						Id:   "guest",
						Role: 4,
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "tenant viewer sends get request",
			req: &apiv1.TenantServiceGetRequest{
				Login: "me",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_VIEWER,
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{Id: "me"}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{
					Meta: &mdmv1.Meta{Id: "me"},
				}}, nil)

				mock.On("ListTenantMembers", tmock.Anything, &mdmv1.ListTenantMembersRequest{TenantId: "me"}).Return(&mdmv1.ListTenantMembersResponse{
					Tenants: []*mdmv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "me"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdmv1.Tenant{
								Meta: &mdmv1.Meta{Id: "viewer"},
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: apiv1.ProjectRole_PROJECT_ROLE_VIEWER.String(),
							},
						},
					},
				}, nil)
			},
			want: &apiv1.TenantServiceGetResponse{Tenant: &apiv1.Tenant{
				Login: "me",
			},
				TenantMembers: []*apiv1.TenantMember{
					{
						Id:   "me",
						Role: 1,
					},
					{
						Id:   "viewer",
						Role: 3,
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "tenant guest sends get request",
			req: &apiv1.TenantServiceGetRequest{
				Login: "me",
			},
			tenantRole: apiv1.TenantRole_TENANT_ROLE_GUEST,
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{Id: "me"}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{
					Meta: &mdmv1.Meta{
						Id: "me",
						Annotations: map[string]string{
							tutil.TagEmail: "mail@me.com",
						},
					},
					Name:        "name",
					Description: "description",
				}}, nil)
			},
			want: &apiv1.TenantServiceGetResponse{Tenant: &apiv1.Tenant{
				Login:       "me",
				Name:        "name",
				Description: "description",
				Email:       "",
			},
			},
			wantErr: nil,
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
					tt.req.Login: tt.tenantRole,
				},
			})

			s := &tenantServiceServer{
				log:          slog.Default(),
				masterClient: newMasterdataMockClient(t, tt.tenantServiceMock, tt.tenantMemberServiceMock, nil, nil),
				inviteStore:  nil,
				tokenStore:   tokenStore,
			}

			result, err := s.Get(ctx, connect.NewRequest(tt.req))
			require.NoError(t, err)
			assert.Equal(t, result.Msg.Tenant, tt.want.Tenant)
		})
	}
}
