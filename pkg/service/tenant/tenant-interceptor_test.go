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

	mdmv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdmv1mock "github.com/metal-stack/masterdata-api/api/v1/mocks"
	"github.com/metal-stack/metal-go/api/client/ip"
	"github.com/metal-stack/metal-go/api/client/network"
	"github.com/metal-stack/metal-go/api/models"
	metalmock "github.com/metal-stack/metal-go/test/client"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/pkg/testcommon"

	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_tenantInterceptor_WrapUnary(t *testing.T) {
	logger := slog.Default()
	tests := []struct {
		name               string
		ip                 *apiv1.IPServiceAllocateRequest
		projectServiceMock func(mock *mdmv1mock.ProjectServiceClient)
		tenantServiceMock  func(mock *mdmv1mock.TenantServiceClient)
		metalMocks         *metalmock.MetalMockFns
		want               *apiv1.IPServiceAllocateResponse
		wantErr            *connect.Error
	}{
		{
			name: "create ip with existing project",
			ip: &apiv1.IPServiceAllocateRequest{
				Project: "p1",
			},
			projectServiceMock: func(mock *mdmv1mock.ProjectServiceClient) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{
					Id: "p1",
				}).Return(&mdmv1.ProjectResponse{Project: &mdmv1.Project{Meta: &mdmv1.Meta{Id: "p1"}, Name: "Project 1", TenantId: "t1"}}, nil)
			},
			tenantServiceMock: func(mock *mdmv1mock.TenantServiceClient) {
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
			projectServiceMock: func(mock *mdmv1mock.ProjectServiceClient) {
				mock.On("Get", tmock.Anything, &mdmv1.ProjectGetRequest{
					Id: "p2",
				}).Return(nil, fmt.Errorf("project p2 not found"))
			},
			want:    nil,
			wantErr: connect.NewError(connect.CodeNotFound, fmt.Errorf("error fetching cache entry: unable to get project: project p2 not found")),
		},
	}
	for _, tt := range tests {
		tt := tt

		_, client := metalmock.NewMetalMockClient(t, tt.metalMocks)

		ipService := ipservice.New(ipservice.Config{
			Log:         logger,
			MetalClient: client,
		})

		tenantInterceptor := newMockedTenantServiceInterceptor(tt.tenantServiceMock, tt.projectServiceMock)

		mux := http.NewServeMux()
		mux.Handle(apiv1connect.NewIPServiceHandler(ipService, connect.WithInterceptors(tenantInterceptor)))

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
		t.Run(tt.name, func(t *testing.T) {
			for _, client := range clients {
				got, err := client.Allocate(context.Background(), connect.NewRequest(tt.ip))

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
