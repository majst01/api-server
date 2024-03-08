package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"connectrpc.com/otelconnect"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/metal-stack/api-server/pkg/auth"
	"github.com/metal-stack/api-server/pkg/certs"
	ratelimiter "github.com/metal-stack/api-server/pkg/rate-limiter"
	"github.com/metal-stack/api-server/pkg/service/health"
	"github.com/metal-stack/api-server/pkg/service/ip"
	"github.com/metal-stack/api-server/pkg/service/method"
	"github.com/metal-stack/api-server/pkg/service/project"
	"github.com/metal-stack/api-server/pkg/service/tenant"
	"github.com/metal-stack/api-server/pkg/service/token"
	"github.com/metal-stack/api-server/pkg/service/version"
	tokencommon "github.com/metal-stack/api-server/pkg/token"
	"github.com/metal-stack/api-server/pkg/validation"
	"github.com/metal-stack/metal-lib/auditing"

	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"github.com/metal-stack/api/go/permissions"
	mdm "github.com/metal-stack/masterdata-api/pkg/client"
)

type config struct {
	HttpServerEndpoint                  string
	MetricsServerEndpoint               string
	FrontEndUrl                         string
	ServerHttpURL                       string
	Log                                 *slog.Logger
	MasterClient                        mdm.Client
	Auditing                            auditing.Auditing
	Stage                               string
	RedisAddr                           string
	RedisPassword                       string
	AdminOrgs                           []string
	MaxRequestsPerMinuteToken           int
	MaxRequestsPerMinuteUnauthenticated int
}
type server struct {
	c   config
	log *slog.Logger
}

func newServer(c config) *server {
	return &server{
		c:   c,
		log: c.Log,
	}
}

func (s *server) Run() error {
	tokenRedisClient, err := createRedisClient(s.log, s.c.RedisAddr, s.c.RedisPassword, redisDatabaseTokens)
	if err != nil {
		return err
	}
	ratelimitRedisClient, err := createRedisClient(s.log, s.c.RedisAddr, s.c.RedisPassword, redisDatabaseRateLimiting)
	if err != nil {
		return err
	}
	inviteRedisClient, err := createRedisClient(s.log, s.c.RedisAddr, s.c.RedisPassword, redisDatabaseInvites)
	if err != nil {
		return err
	}
	tokenStore := tokencommon.NewRedisStore(tokenRedisClient)
	certStore := certs.NewRedisStore(&certs.Config{
		RedisClient: tokenRedisClient,
	})
	inviteStore := project.NewRedisStore(inviteRedisClient)

	authcfg := auth.Config{
		Log:            s.log,
		CertStore:      certStore,
		AllowedIssuers: []string{s.c.ServerHttpURL},
	}
	authz, err := auth.New(authcfg)
	if err != nil {
		log.Fatalf("Unable to initialize authz interceptor: %s", err)
	}

	// metrics interceptor
	exporter, err := prometheus.New()
	if err != nil {
		return err
	}
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	metricsInterceptor, err := otelconnect.NewInterceptor(otelconnect.WithMeterProvider(provider))
	if err != nil {
		return err
	}

	tenantInterceptor := tenant.NewInterceptor(s.log, s.c.MasterClient)
	validationInterceptor := validation.NewInterceptor(s.log)
	ratelimitInterceptor := ratelimiter.NewInterceptor(&ratelimiter.Config{
		Log:                                 s.log,
		RedisClient:                         ratelimitRedisClient,
		MaxRequestsPerMinuteToken:           s.c.MaxRequestsPerMinuteToken,
		MaxRequestsPerMinuteUnauthenticated: s.c.MaxRequestsPerMinuteUnauthenticated,
	})
	tokenWhitelistInterceptor := tokencommon.NewTokenWhitelistInterceptor(s.log, tokenRedisClient)

	allInterceptors := []connect.Interceptor{metricsInterceptor, authz, tokenWhitelistInterceptor, ratelimitInterceptor, validationInterceptor, tenantInterceptor}
	if s.c.Auditing != nil {
		servicePermissions := permissions.GetServicePermissions()
		shouldAudit := func(fullMethod string) bool {
			shouldAudit, ok := servicePermissions.Auditable[fullMethod]
			if !ok {
				s.c.Log.Warn("method not found in permissions, audit implicitly", "method", fullMethod)
				return true
			}
			return shouldAudit
		}
		auditInterceptor, err := auditing.NewConnectInterceptor(s.c.Auditing, s.log, shouldAudit)
		if err != nil {
			return fmt.Errorf("unable to create auditing interceptor:%w", err)
		}
		allInterceptors = append(allInterceptors, auditInterceptor)
	}
	interceptors := connect.WithInterceptors(allInterceptors...)

	methodService := method.New()
	tenantService := tenant.New(tenant.Config{
		Log:          s.log,
		MasterClient: s.c.MasterClient,
	})
	projectService := project.New(project.Config{
		Log:          s.log,
		MasterClient: s.c.MasterClient,
		InviteStore:  inviteStore,
	})
	ipService := ip.New(ip.Config{Log: s.log})
	tokenService := token.New(token.Config{
		Log:           s.log,
		CertStore:     certStore,
		TokenStore:    tokenStore,
		Issuer:        s.c.ServerHttpURL,
		AdminSubjects: s.c.AdminOrgs,
	})
	versionService := version.New(version.Config{Log: s.log})
	healthService, err := health.New(health.Config{Ctx: context.Background(), Log: s.log, HealthcheckInterval: 1 * time.Minute})
	if err != nil {
		return fmt.Errorf("unable to initialize health service %w", err)
	}

	mux := http.NewServeMux()

	// Register the services
	mux.Handle(apiv1connect.NewTokenServiceHandler(tokenService, interceptors))
	mux.Handle(apiv1connect.NewTenantServiceHandler(tenantService, interceptors))
	mux.Handle(apiv1connect.NewProjectServiceHandler(projectService, interceptors))
	mux.Handle(apiv1connect.NewIPServiceHandler(ipService, interceptors))
	mux.Handle(apiv1connect.NewMethodServiceHandler(methodService, interceptors))

	mux.Handle(apiv1connect.NewVersionServiceHandler(versionService, interceptors))
	mux.Handle(apiv1connect.NewHealthServiceHandler(healthService, interceptors))

	allServiceNames := permissions.GetServices()
	// Static HealthCheckers
	checker := grpchealth.NewStaticChecker(allServiceNames...)
	mux.Handle(grpchealth.NewHandler(checker))

	// enable remote service listing by enabling reflection
	reflector := grpcreflect.NewStaticReflector(allServiceNames...)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	// Add all authentification handlers in one go

	apiServer := &http.Server{
		Addr:              s.c.HttpServerEndpoint,
		Handler:           h2c.NewHandler(newCORS().Handler(mux), &http2.Server{}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}
	s.log.Info("serving http on", "addr", apiServer.Addr)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		if err := apiServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("HTTP listen and serve", "error", err)
			os.Exit(1)
		}
	}()

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	ms := &http.Server{
		Addr:              s.c.MetricsServerEndpoint,
		Handler:           metricsMux,
		ReadHeaderTimeout: time.Minute,
	}
	go func() {
		s.log.Info("serving metrics at", "addr", ms.Addr+"/metrics")
		err := ms.ListenAndServe()
		if err != nil {
			s.log.Error("unable to start metric endpoint", "error", err)
			return
		}
	}()

	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return apiServer.Shutdown(ctx)
}

// newCORS
// TODO review what is strictly required
func newCORS() *cors.Cors {
	// To let web developers play with the demo service from browsers, we need a
	// very permissive CORS setup.
	return cors.New(cors.Options{
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowOriginFunc: func(origin string) bool {
			// Allow all origins, which effectively disables CORS.
			return true
		},
		AllowedHeaders: []string{"*"},
		ExposedHeaders: []string{
			// Content-Type is in the default safelist.
			"Accept",
			"Accept-Encoding",
			"Accept-Post",
			"Connect-Accept-Encoding",
			"Connect-Content-Encoding",
			"Connect-Protocol-Version",
			"Content-Encoding",
			"Grpc-Accept-Encoding",
			"Grpc-Encoding",
			"Grpc-Message",
			"Grpc-Status",
			"Grpc-Status-Details-Bin",
		},
		// Let browsers cache CORS information for longer, which reduces the number
		// of preflight requests. Any changes to ExposedHeaders won't take effect
		// until the cached data expires. FF caps this value at 24h, and modern
		// Chrome caps it at 2h.
		MaxAge: int(2 * time.Hour / time.Second),
	})
}
