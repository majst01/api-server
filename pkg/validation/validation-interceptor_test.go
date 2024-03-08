package validation_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/validation"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"github.com/stretchr/testify/require"
)

func TestWithValidator(t *testing.T) {
	t.Parallel()
	interceptor := validation.NewInterceptor(slog.Default())

	mux := http.NewServeMux()
	mux.Handle(apiv1connect.TokenServiceCreateProcedure, connect.NewUnaryHandler(
		apiv1connect.TokenServiceCreateProcedure,
		createToken,
		connect.WithInterceptors(interceptor),
	))
	srv := startHTTPServer(t, mux)

	req := connect.NewRequest(&apiv1.TokenServiceCreateRequest{
		Description: "",
	})
	_, err := apiv1connect.NewTokenServiceClient(srv.Client(), srv.URL).Create(context.Background(), req)
	require.Error(t, err)
	require.EqualError(t, err, "failed_precondition: request validation failed invalid TokenServiceCreateRequest.Description: value length must be between 2 and 256 runes, inclusive")
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func startHTTPServer(tb testing.TB, h http.Handler) *httptest.Server {
	tb.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.Start()
	tb.Cleanup(srv.Close)
	return srv
}

func createToken(_ context.Context, req *connect.Request[apiv1.TokenServiceCreateRequest]) (*connect.Response[apiv1.TokenServiceCreateResponse], error) {
	return connect.NewResponse(&apiv1.TokenServiceCreateResponse{Token: &apiv1.Token{Uuid: "abc"}}), nil
}
