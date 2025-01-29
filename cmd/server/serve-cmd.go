package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/avast/retry-go/v4"
	compress "github.com/klauspost/connect-compress/v2"

	ipamv1 "github.com/metal-stack/go-ipam/api/v1"
	ipamv1connect "github.com/metal-stack/go-ipam/api/v1/apiv1connect"
	mdm "github.com/metal-stack/masterdata-api/pkg/client"
	"github.com/metal-stack/metal-lib/auditing"
	"github.com/metal-stack/v"
	"github.com/redis/go-redis/v9"
	"github.com/urfave/cli/v2"
	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

var serveCmd = &cli.Command{
	Name:  "serve",
	Usage: "start the api server",
	Flags: []cli.Flag{
		logLevelFlag,
		httpServerEndpointFlag,
		metricServerEndpointFlag,
		sessionSecretFlag,
		frontEndUrlFlag,
		serverHttpUrlFlag,
		masterdataApiHostnameFlag,
		masterdataApiPortFlag,
		masterdataApiHmacFlag,
		masterdataApiCAPathFlag,
		masterdataApiCertPathFlag,
		masterdataApiCertKeyPathFlag,
		rethinkdbAddressesFlag,
		rethinkdbDBFlag,
		rethinkdbDBNameFlag,
		rethinkdbPasswordFlag,
		rethinkdbUserFlag,
		auditingUrlFlag,
		auditingApiKeyFlag,
		auditingEnabledFlag,
		auditingIndexPrefixFlag,
		auditingIndexIntervalFlag,
		auditingIndexKeepFlag,
		stageFlag,
		redisAddrFlag,
		redisPasswordFlag,
		adminOrgsFlag,
		maxRequestsPerMinuteFlag,
		maxRequestsPerMinuteUnauthenticatedFlag,
		ipamGrpcEndpointFlag,
	},
	Action: func(ctx *cli.Context) error {
		log, level, err := createLoggers(ctx)
		if err != nil {
			return fmt.Errorf("unable to create logger %w", err)
		}
		audit, err := createAuditingClient(ctx, log)
		if err != nil {
			log.Error("unable to create auditing client", "error", err)
			os.Exit(1)
		}

		redisAddr := ctx.String(redisAddrFlag.Name)
		stage := ctx.String(stageFlag.Name)

		rethinkDBSession, err := createRedisDBClient(ctx)
		if err != nil {
			log.Error("unable to create rethinkdb client", "error", err)
			os.Exit(1)
		}

		ipam, err := createIpamClient(ctx, log)
		if err != nil {
			log.Error("unable to create ipam client", "error", err)
			os.Exit(1)
		}

		c := config{
			HttpServerEndpoint:                  ctx.String(httpServerEndpointFlag.Name),
			MetricsServerEndpoint:               ctx.String(metricServerEndpointFlag.Name),
			FrontEndUrl:                         ctx.String(frontEndUrlFlag.Name),
			Log:                                 log,
			MasterClient:                        retryConnectMasterdataClient(ctx, log),
			ServerHttpURL:                       ctx.String(serverHttpUrlFlag.Name),
			Auditing:                            audit,
			Stage:                               stage,
			RedisAddr:                           redisAddr,
			RedisPassword:                       ctx.String(redisPasswordFlag.Name),
			AdminOrgs:                           ctx.StringSlice(adminOrgsFlag.Name),
			MaxRequestsPerMinuteToken:           ctx.Int(maxRequestsPerMinuteFlag.Name),
			MaxRequestsPerMinuteUnauthenticated: ctx.Int(maxRequestsPerMinuteUnauthenticatedFlag.Name),
			RethinkDB:                           ctx.String(rethinkdbDBFlag.Name),
			RethinkDBSession:                    rethinkDBSession,
			Ipam:                                ipam,
		}

		log.Info("running api-server", "version", v.V, "level", level, "http endpoint", c.HttpServerEndpoint)
		s := newServer(c)
		if err := s.Run(); err != nil {
			log.Error("unable to execute server", "error", err)
			os.Exit(1)
		}
		return nil
	},
}

// retryConnectMasterdataClient creates a client to the masterdata-api
// this is a blocking operation
func retryConnectMasterdataClient(cli *cli.Context, logger *slog.Logger) mdm.Client {
	var err error
	var client mdm.Client
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		client, err = mdm.NewClient(ctx,
			cli.String("masterdata-api-hostname"),
			cli.Int("masterdata-api-port"),
			cli.String("masterdata-api-cert-path"),
			cli.String("masterdata-api-cert-key-path"),
			cli.String("masterdata-api-ca-path"),
			cli.String("masterdata-api-hmac"),
			false, // TLSSkipInsecure
			slog.Default(),
		)
		if err == nil {
			defer cancel()
			break
		}
		cancel()
		logger.Error("unable to initialize masterdata-api client, retrying...", "error", err)
		time.Sleep(3 * time.Second)
	}

	logger.Info("masterdata client initialized")

	return client
}

func createRedisDBClient(cli *cli.Context) (*r.Session, error) {
	session, err := r.Connect(r.ConnectOpts{
		Addresses: cli.StringSlice("db-addr"),
		Database:  cli.String("db-name"),
		Username:  cli.String("db-user"),
		Password:  cli.String("db-password"),
		MaxIdle:   10,
		MaxOpen:   20,
	})
	return session, err
}

// createAuditingClient creates a new auditing client
// Can return nil,nil if auditing is disabled!
func createAuditingClient(cli *cli.Context, log *slog.Logger) (auditing.Auditing, error) {
	auditingEnabled := cli.Bool("auditing-enabled")
	if !auditingEnabled {
		return nil, nil
	}
	c := auditing.Config{
		URL:              cli.String("auditing-url"),
		APIKey:           cli.String("auditing-api-key"),
		Log:              log,
		IndexPrefix:      cli.String("auditing-index-prefix"),
		RotationInterval: auditing.Interval(cli.String("auditing-index-interval")),
		Keep:             cli.Int64("auditing-index-keep"),
	}
	return auditing.New(c)
}

type RedisDatabase string

const (
	redisDatabaseTokens       RedisDatabase = "token"
	redisDatabaseRateLimiting RedisDatabase = "rate-limiter"
	redisDatabaseInvites      RedisDatabase = "invite"
)

func createRedisClient(logger *slog.Logger, address, password string, dbName RedisDatabase) (*redis.Client, error) {
	db := 0
	switch dbName {
	case redisDatabaseTokens:
		db = 0
	case redisDatabaseRateLimiting:
		db = 1
	case redisDatabaseInvites:
		db = 2
	default:
		return nil, fmt.Errorf("invalid db name: %s", dbName)
	}

	// If we see performance Issues we can try this client
	// client, err := rueidis.NewClient(rueidis.ClientOption{InitAddress: c.RedisAddresses})
	// if err != nil {
	// 	return nil, err
	// }

	if address == "" {
		logger.Warn("no redis address given, start in-memory redis database")
		mr, _ := miniredis.Run()
		address = mr.Addr()
	}

	client := redis.NewClient(&redis.Options{
		Addr:       address,
		Password:   password,
		DB:         db,
		ClientName: "api-server",
	})
	pong, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, fmt.Errorf("unable to create redis client:%w", err)
	}

	if strings.ToLower(pong) != "pong" {
		return nil, fmt.Errorf("unable to create redis client, did not get PONG result:%q", pong)
	}

	return client, nil
}

func createIpamClient(cli *cli.Context, log *slog.Logger) (ipamv1connect.IpamServiceClient, error) {
	ipamgrpcendpoint := cli.String(ipamGrpcEndpointFlag.Name)

	ipamService := ipamv1connect.NewIpamServiceClient(
		http.DefaultClient,
		ipamgrpcendpoint,
		connect.WithGRPC(),
		compress.WithAll(compress.LevelBalanced),
	)

	err := retry.Do(func() error {
		version, err := ipamService.Version(context.Background(), connect.NewRequest(&ipamv1.VersionRequest{}))
		if err != nil {
			return err
		}
		log.Info("connected to ipam service", "version", version.Msg)
		return nil
	})

	if err != nil {
		log.Error("unable to connect to ipam service", "error", err)
		return nil, err
	}

	log.Info("ipam initialized")
	return ipamService, nil
}
