package method

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/api/go/metalstack/api/v1/apiv1connect"
	"github.com/metal-stack/api/go/permissions"
)

type methodServiceServer struct {
	servicePermissions *permissions.ServicePermissions
}

func New() apiv1connect.MethodServiceHandler {
	servicePermissions := permissions.GetServicePermissions()

	return &methodServiceServer{
		servicePermissions: servicePermissions,
	}
}

func (m *methodServiceServer) List(ctx context.Context, _ *connect.Request[apiv1.MethodServiceListRequest]) (*connect.Response[apiv1.MethodServiceListResponse], error) {
	token, ok := token.TokenFromContext(ctx)
	if !ok || token == nil {
		// only list public methods when there is no token

		var methods []string
		for m := range m.servicePermissions.Visibility.Public {
			methods = append(methods, m)
		}

		return connect.NewResponse(&apiv1.MethodServiceListResponse{
			Methods: methods,
		}), nil
	}

	var (
		methods      []string
		isAdminToken = IsAdminToken(token)
	)
	for m := range m.servicePermissions.Methods {
		if isAdminToken {
			methods = append(methods, m)
			continue
		}

		if strings.HasPrefix(m, "/metalstack.api.v1") { // TODO: add all methods that do not require admin permissions
			methods = append(methods, m)
		}
	}

	return connect.NewResponse(&apiv1.MethodServiceListResponse{
		Methods: methods,
	}), nil
}

func (m *methodServiceServer) TokenScopedList(ctx context.Context, _ *connect.Request[apiv1.MethodServiceTokenScopedListRequest]) (*connect.Response[apiv1.MethodServiceTokenScopedListResponse], error) {
	token, ok := token.TokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("no token found in request"))
	}

	return connect.NewResponse(&apiv1.MethodServiceTokenScopedListResponse{
		Permissions:  token.Permissions,
		ProjectRoles: token.ProjectRoles,
		TenantRoles:  token.TenantRoles,
		AdminRole:    token.AdminRole,
	}), nil
}
