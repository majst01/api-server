package test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	goipam "github.com/metal-stack/go-ipam"
	ipamv1connect "github.com/metal-stack/go-ipam/api/v1/apiv1connect"
	"github.com/metal-stack/go-ipam/pkg/service"
)

func StartIpam(t *testing.T) ipamv1connect.IpamServiceClient {

	ctx := context.Background()
	mux := http.NewServeMux()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	mux.Handle(ipamv1connect.NewIpamServiceHandler(
		service.New(log, goipam.New(ctx)),
	))
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()

	ipamclient := ipamv1connect.NewIpamServiceClient(
		server.Client(),
		server.URL,
	)
	return ipamclient
}
