package project

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/metal-stack/api/go/metalstack/api/v1"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdmv1mock "github.com/metal-stack/masterdata-api/api/v1/mocks"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/pkg/testcommon"
	"github.com/stretchr/testify/mock"

	tutil "github.com/metal-stack/api-server/pkg/tenant"
)

func newMasterdataMockClient(
	t *testing.T,
	tenantServiceMock func(mock *mock.Mock),
	tenantMemberServiceMock func(mock *mock.Mock),
	projectServiceMock func(mock *mock.Mock),
	projectMemberServiceMock func(mock *mock.Mock),
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

func TestGetProjectsAndTenants(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                     string
		tenantServiceMock        func(mock *mock.Mock)
		tenantMemberServiceMock  func(mock *mock.Mock)
		projectServiceMock       func(mock *mock.Mock)
		projectMemberServiceMock func(mock *mock.Mock)
		want                     *ProjectsAndTenants
		wantErr                  error
	}{
		{
			name: "no projects or tenants",
			want: nil,
			tenantServiceMock: func(mock *mock.Mock) {
				mock.On("FindParticipatingProjects", ctx, &mdcv1.FindParticipatingProjectsRequest{
					TenantId:         "test-user",
					IncludeInherited: pointer.Pointer(true),
				}).Return(&mdcv1.FindParticipatingProjectsResponse{}, nil)
				mock.On("FindParticipatingTenants", ctx, &mdcv1.FindParticipatingTenantsRequest{
					TenantId:         "test-user",
					IncludeInherited: pointer.Pointer(true),
				}).Return(&mdcv1.FindParticipatingTenantsResponse{}, nil)
			},
			wantErr: fmt.Errorf("unable to find a default project for user: test-user"),
		},
		{
			name: "real world scenario",
			tenantServiceMock: func(mock *mock.Mock) {
				mock.On("FindParticipatingProjects", ctx, &mdcv1.FindParticipatingProjectsRequest{
					TenantId:         "test-user",
					IncludeInherited: pointer.Pointer(true),
				}).Return(&mdcv1.FindParticipatingProjectsResponse{
					Projects: []*mdcv1.ProjectWithMembershipAnnotations{
						{
							Project: &mdcv1.Project{
								Meta: &mdcv1.Meta{
									Id: "4ec2dcf8-19e3-437d-96e5-dcde95dc6e55",
									Annotations: map[string]string{
										DefaultProjectAnnotation: strconv.FormatBool(true),
									},
								},
								Name:        "default-project",
								Description: "default-project of user test-user",
								TenantId:    "test-user",
							},
							ProjectAnnotations: map[string]string{
								ProjectRoleAnnotation: v1.ProjectRole_PROJECT_ROLE_OWNER.String(),
							},
						},
						{
							Project: &mdcv1.Project{
								Meta: &mdcv1.Meta{
									Id: "c1829741-f398-412c-8c0a-284e298d1a81",
									Annotations: map[string]string{
										DefaultProjectAnnotation: strconv.FormatBool(true),
									},
								},
								Name:        "default-project",
								Description: "default-project of user b",
								TenantId:    "b",
							},
							ProjectAnnotations: map[string]string{
								ProjectRoleAnnotation: v1.ProjectRole_PROJECT_ROLE_OWNER.String(),
							},
						},
						{
							Project: &mdcv1.Project{
								Meta: &mdcv1.Meta{
									Id: "a5bf9cef-b01b-4f68-be92-756bd3691b80",
								},
								Name:        "My project C",
								Description: "Created by user c",
								TenantId:    "c",
							},
							ProjectAnnotations: map[string]string{
								ProjectRoleAnnotation: v1.ProjectRole_PROJECT_ROLE_VIEWER.String(),
							},
						},
					},
				}, nil)
				mock.On("FindParticipatingTenants", ctx, &mdcv1.FindParticipatingTenantsRequest{
					TenantId:         "test-user",
					IncludeInherited: pointer.Pointer(true),
				}).Return(&mdcv1.FindParticipatingTenantsResponse{
					Tenants: []*mdcv1.TenantWithMembershipAnnotations{
						{
							Tenant: &mdcv1.Tenant{
								Meta: &mdcv1.Meta{
									Id: "test-user",
									Annotations: map[string]string{
										tutil.TagAvatarURL: "https://example.jpg",
									},
								},
								Name: "test-user",
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: v1.TenantRole_TENANT_ROLE_OWNER.String(),
							},
						},
						{
							Tenant: &mdcv1.Tenant{
								Meta: &mdcv1.Meta{
									Id: "tenant-d",
									Annotations: map[string]string{
										tutil.TagAvatarURL: "https://example.jpg",
									},
								},
								Name:        "Tenant D",
								Description: "This is tenant D",
							},
							TenantAnnotations: map[string]string{
								tutil.TenantRoleAnnotation: v1.TenantRole_TENANT_ROLE_EDITOR.String(),
							},
						},
					},
				}, nil)
			},
			want: &ProjectsAndTenants{
				Projects: []*v1.Project{
					{
						Uuid:             "4ec2dcf8-19e3-437d-96e5-dcde95dc6e55",
						Name:             "default-project",
						Description:      "default-project of user test-user",
						Tenant:           "test-user",
						IsDefaultProject: true,
						AvatarUrl:        pointer.Pointer(""),
					},
					{
						Uuid:             "c1829741-f398-412c-8c0a-284e298d1a81",
						Name:             "default-project",
						Description:      "default-project of user b",
						Tenant:           "b",
						IsDefaultProject: true,
						AvatarUrl:        pointer.Pointer(""),
					},
					{
						Uuid:             "a5bf9cef-b01b-4f68-be92-756bd3691b80",
						Name:             "My project C",
						Description:      "Created by user c",
						Tenant:           "c",
						IsDefaultProject: false,
						AvatarUrl:        pointer.Pointer(""),
					},
				},
				DefaultProject: &v1.Project{
					Uuid:             "4ec2dcf8-19e3-437d-96e5-dcde95dc6e55",
					Name:             "default-project",
					Description:      "default-project of user test-user",
					Tenant:           "test-user",
					IsDefaultProject: true,
					AvatarUrl:        pointer.Pointer(""),
				},
				Tenants: []*v1.Tenant{
					{
						Login:     "test-user",
						Name:      "test-user",
						AvatarUrl: "https://example.jpg",
					},
					{
						Login:       "tenant-d",
						Name:        "Tenant D",
						AvatarUrl:   "https://example.jpg",
						Description: "This is tenant D",
					},
				},
				DefaultTenant: &v1.Tenant{
					Login:     "test-user",
					Name:      "test-user",
					AvatarUrl: "https://example.jpg",
				},
				ProjectRoles: map[string]v1.ProjectRole{
					"4ec2dcf8-19e3-437d-96e5-dcde95dc6e55": v1.ProjectRole_PROJECT_ROLE_OWNER,
					"a5bf9cef-b01b-4f68-be92-756bd3691b80": v1.ProjectRole_PROJECT_ROLE_VIEWER,
					"c1829741-f398-412c-8c0a-284e298d1a81": v1.ProjectRole_PROJECT_ROLE_OWNER,
				},
				TenantRoles: map[string]v1.TenantRole{
					"tenant-d":  v1.TenantRole_TENANT_ROLE_EDITOR,
					"test-user": v1.TenantRole_TENANT_ROLE_OWNER,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := newMasterdataMockClient(t, tt.tenantServiceMock, tt.tenantMemberServiceMock, tt.projectServiceMock, tt.projectMemberServiceMock)

			got, err := GetProjectsAndTenants(ctx, mc, "test-user")

			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
			if diff := cmp.Diff(tt.want, got, testcommon.IgnoreUnexported()); diff != "" {
				t.Errorf("diff (+got -want):\n %s", diff)
			}
		})
	}
}
