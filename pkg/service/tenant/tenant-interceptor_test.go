package tenant

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"

	ipservice "github.com/metal-stack/api-server/pkg/service/ip"
	tutil "github.com/metal-stack/api-server/pkg/tenant"
	"github.com/metal-stack/api-server/pkg/token"

	mdmv1 "github.com/metal-stack/masterdata-api/api/v1"
	"github.com/metal-stack/metal-go/api/client/ip"
	"github.com/metal-stack/metal-go/api/client/network"
	"github.com/metal-stack/metal-go/api/models"
	metalmock "github.com/metal-stack/metal-go/test/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/pkg/testcommon"
	"github.com/metal-stack/security"

	"github.com/stretchr/testify/assert"
	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_tenantInterceptor_WrapUnary(t *testing.T) {
	logger := slog.Default()
	tests := []struct {
		name               string
		ip                 *apiv1.IPServiceAllocateRequest
		projectServiceMock func(mock *tmock.Mock)
		tenantServiceMock  func(mock *tmock.Mock)
		metalMocks         *metalmock.MetalMockFns
		want               *apiv1.IPServiceAllocateResponse
		wantErr            *connect.Error
	}{
		{
			name: "create ip with existing project",
			ip: &apiv1.IPServiceAllocateRequest{
				Project: "p1",
			},
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{
					Id: "p1",
				}).Return(&mdmv1.ProjectResponse{Project: &mdmv1.Project{Meta: &mdmv1.Meta{Id: "p1"}, Name: "Project 1", TenantId: "t1"}}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{
					Id: "t1",
				}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{Meta: &mdmv1.Meta{Id: "t1"}}}, nil)
			},
			metalMocks: &metalmock.MetalMockFns{
				Network: func(mock *tmock.Mock) {
					mock.On("FindNetworks", tmock.Anything, nil).Return(&network.FindNetworksOK{Payload: []*models.V1NetworkResponse{{ID: pointer.Pointer("internet")}}}, nil)
				},
				IP: func(mock *tmock.Mock) {
					mock.On("AllocateIP", ip.NewAllocateIPParams().WithBody(&models.V1IPAllocateRequest{
						Projectid: pointer.Pointer("p1"),
						Networkid: pointer.Pointer("internet"),
						Type:      pointer.Pointer("ephemeral"),
					}), nil).Return(&ip.AllocateIPCreated{Payload: &models.V1IPResponse{Ipaddress: pointer.Pointer("1.2.3.4"), Projectid: pointer.Pointer("p1"), Networkid: pointer.Pointer("internet")}}, nil)
				},
			},
			want:    &apiv1.IPServiceAllocateResponse{},
			wantErr: nil,
		},
		{
			name: "create ip with non-existing project",
			ip: &apiv1.IPServiceAllocateRequest{
				Project: "p2",
			},
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{
					Id: "p2",
				}).Return(nil, fmt.Errorf("project p2 not found"))
			},
			want:    nil,
			wantErr: connect.NewError(connect.CodeInternal, fmt.Errorf("error fetching cache entry: unable to get project: project p2 not found")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, client := metalmock.NewMetalMockClient(t, tt.metalMocks)

			ipService := ipservice.New(ipservice.Config{
				Log:              logger,
				MetalClient:      client,
			})

			mc := newMasterdataMockClient(t, tt.tenantServiceMock, nil, tt.projectServiceMock, nil)
			interceptor := NewInterceptor(logger, mc)

			mux := http.NewServeMux()
			mux.Handle(apiv1connect.NewIPServiceHandler(ipService, connect.WithInterceptors(interceptor)))

			server := httptest.NewUnstartedServer(mux)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()

			connectClient := apiv1connect.NewIPServiceClient(
				server.Client(),
				server.URL,
			)
			grpcClient := apiv1connect.NewIPServiceClient(
				server.Client(),
				server.URL,
				connect.WithGRPC(),
			)
			clients := []apiv1connect.IPServiceClient{connectClient, grpcClient}

			for _, client := range clients {
				ctx := token.ContextWithToken(context.Background(), &apiv1.Token{
					UserId: "t1",
				})

				got, err := client.Allocate(ctx, connect.NewRequest(tt.ip))

				if err != nil {
					if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
						t.Errorf("error diff (+got -want):\n %s", diff)
					}
				} else {
					require.Equal(t, got.Msg.Ip.Project, tt.ip.Project)
					require.Equal(t, got.Msg.Ip.Name, tt.ip.Name)
					require.NotEmpty(t, got.Msg.Ip.Ip)
				}
			}
		})
	}
}

func Test_tenantInterceptor_AuditingCtx(t *testing.T) {
	tests := []struct {
		name               string
		req                connect.AnyRequest
		token              *apiv1.Token
		projectServiceMock func(mock *tmock.Mock)
		tenantServiceMock  func(mock *tmock.Mock)
		wantUser           *security.User
		wantErr            error
	}{
		{
			name: "anonymous request",
			req:  connect.NewRequest(&apiv1.HealthServiceGetRequest{}),
			wantUser: &security.User{
				EMail:   "",
				Name:    "",
				Groups:  []security.ResourceAccess{},
				Tenant:  "",
				Issuer:  "",
				Subject: "",
			},
			wantErr: nil,
		},
		{
			name: "self request is best effort",
			req:  connect.NewRequest(&apiv1.ProjectServiceListRequest{}),
			token: &apiv1.Token{
				Uuid:   "a-uuid",
				UserId: "user@github",
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{
					Id: "user@github",
				}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{Meta: &mdmv1.Meta{Id: "user@github", Annotations: map[string]string{tutil.TagEmail: "mail@user"}}}}, nil)
			},
			wantUser: &security.User{
				EMail:   "mail@user",
				Name:    "",
				Groups:  []security.ResourceAccess{},
				Tenant:  "user@github",
				Issuer:  "",
				Subject: "user@github",
			},
			wantErr: nil,
		},
		{
			name: "project request",
			req: connect.NewRequest(&apiv1.IPServiceGetRequest{
				Project: "a-project",
			}),
			token: &apiv1.Token{
				Uuid:   "a-uuid",
				UserId: "user@github",
			},
			projectServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{
					Id: "a-project",
				}).Return(&mdmv1.ProjectResponse{Project: &mdmv1.Project{Meta: &mdmv1.Meta{Id: "a-project"}, Name: "Project A", TenantId: "t1"}}, nil)
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{
					Id: "t1",
				}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{Meta: &mdmv1.Meta{Id: "t1", Annotations: map[string]string{tutil.TagEmail: "mail@t1"}}}}, nil)
			},
			wantUser: &security.User{
				EMail:   "mail@t1",
				Name:    "",
				Groups:  []security.ResourceAccess{},
				Tenant:  "t1",
				Issuer:  "",
				Subject: "user@github",
			},
			wantErr: nil,
		},
		{
			name: "tenant request",
			req: connect.NewRequest(&apiv1.TenantServiceGetRequest{
				Login: "a-tenant",
			}),
			token: &apiv1.Token{
				Uuid:   "a-uuid",
				UserId: "user@github",
			},
			tenantServiceMock: func(mock *tmock.Mock) {
				mock.On("Get", tmock.Anything, &mdmv1.TenantGetRequest{
					Id: "a-tenant",
				}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{Meta: &mdmv1.Meta{Id: "a-tenant", Annotations: map[string]string{tutil.TagEmail: "mail@tenant-a"}}}}, nil)
			},
			wantUser: &security.User{
				EMail:   "mail@tenant-a",
				Name:    "",
				Groups:  []security.ResourceAccess{},
				Tenant:  "a-tenant",
				Issuer:  "",
				Subject: "user@github",
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				ctx = context.Background()
				mc  = newMasterdataMockClient(t, tt.tenantServiceMock, nil, tt.projectServiceMock, nil)
				ti  = NewInterceptor(slog.Default(), mc)

				called = false
				noopFn = func(ctx context.Context, ar connect.AnyRequest) (connect.AnyResponse, error) {
					called = true

					user := security.GetUserFromContext(ctx)
					assert.Equal(t, tt.wantUser, user)

					return nil, nil
				}
			)

			if tt.token != nil {
				ctx = token.ContextWithToken(ctx, tt.token)
			}

			_, err := ti.WrapUnary(noopFn)(ctx, tt.req)
			require.NoError(t, err)

			assert.True(t, called, "request was not forwarded to next")
		})
	}
}
