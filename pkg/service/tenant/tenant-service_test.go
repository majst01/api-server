package tenant

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	mdmv1 "github.com/metal-stack/masterdata-api/api/v1"
	mdmv1mock "github.com/metal-stack/masterdata-api/api/v1/mocks"
	mdc "github.com/metal-stack/masterdata-api/pkg/client"

	"github.com/stretchr/testify/assert"
	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newMockedTenantServiceHandler(tenantServiceMock func(mock *mdmv1mock.TenantServiceClient), projectServiceMock func(mock *mdmv1mock.ProjectServiceClient)) (string, http.Handler) {
	tsc := &mdmv1mock.TenantServiceClient{}
	if tenantServiceMock != nil {
		tenantServiceMock(tsc)
	}
	psc := &mdmv1mock.ProjectServiceClient{}
	if projectServiceMock != nil {
		projectServiceMock(psc)
	}
	pmsc := &mdmv1mock.ProjectMemberServiceClient{}
	mc := mdc.NewMock(psc, tsc, pmsc)
	return apiv1connect.NewTenantServiceHandler(New(
		Config{
			Log:          slog.Default(),
			MasterClient: mc,
		},
	))
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
	mc := mdc.NewMock(psc, tsc, pmsc)
	return NewInterceptor(slog.Default(), mc)
}

func Test_service_Create(t *testing.T) {
	tests := []struct {
		name              string
		tenant            *apiv1.TenantServiceCreateRequest
		tenantServiceMock func(mock *mdmv1mock.TenantServiceClient)
		want              *apiv1.TenantServiceCreateResponse
		wantErr           *connect.Error
	}{
		{
			name: "create user",
			tenant: &apiv1.TenantServiceCreateRequest{
				Tenant: &apiv1.Tenant{
					Login: "t1",
					Name:  "Tenant 1",
				},
			},
			tenantServiceMock: func(mock *mdmv1mock.TenantServiceClient) {
				mock.On("Create", tmock.Anything, &mdmv1.TenantCreateRequest{
					Tenant: &mdmv1.Tenant{Meta: &mdmv1.Meta{
						Id:   "t1",
						Kind: "Tenant",
						Annotations: map[string]string{
							"metal-stack.io/admitted":       "false",
							"metal-stack.io/avatarurl":      "",
							"metal-stack.io/email":          "",
							"metal-stack.io/oauth/provider": "O_AUTH_PROVIDER_UNSPECIFIED",
							"metal-stack.io/emailconsent":   "false",
							"metal-stack.io/onboarded":      "false",
						},
					},
						Name: "Tenant 1",
					}}).Return(&mdmv1.TenantResponse{Tenant: &mdmv1.Tenant{Meta: &mdmv1.Meta{Id: "t1"}, Name: "Tenant 1"}}, nil)
			},
			want: &apiv1.TenantServiceCreateResponse{Tenant: &apiv1.Tenant{
				Login: "t1", Name: "Tenant 1",
			}},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt

		mux := http.NewServeMux()
		mux.Handle(newMockedTenantServiceHandler(tt.tenantServiceMock, nil))

		server := httptest.NewUnstartedServer(mux)
		server.EnableHTTP2 = true
		server.StartTLS()
		defer server.Close()

		connectClient := apiv1connect.NewTenantServiceClient(
			server.Client(),
			server.URL,
		)
		grpcClient := apiv1connect.NewTenantServiceClient(
			server.Client(),
			server.URL,
			connect.WithGRPC(),
		)
		clients := []apiv1connect.TenantServiceClient{connectClient, grpcClient}
		t.Run(tt.name, func(t *testing.T) {
			for _, client := range clients {
				result, err := client.Create(context.Background(), connect.NewRequest(tt.tenant))
				require.NoError(t, err)
				assert.Equal(t, result.Msg.Tenant.Login, tt.want.Tenant.Login)
				assert.Equal(t, result.Msg.Tenant.Name, tt.want.Tenant.Name)
			}
		})
	}
}
