package main

import (
	"log"
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

const (
	stageDEV  = "DEV"
	stagePROD = "PROD"
)

var (
	httpServerEndpointFlag = &cli.StringFlag{
		Name:  "http-server-endpoint",
		Value: "localhost:8080",
		Usage: "http server bind address",
	}
	metricServerEndpointFlag = &cli.StringFlag{
		Name:  "metric-server-endpoint",
		Value: "localhost:2112",
		Usage: "metric server endpoint",
	}
	frontEndUrlFlag = &cli.StringFlag{
		Name:    "front-end-url",
		Value:   "http://localhost:3000",
		Usage:   "URL of the frontend (console)",
		EnvVars: []string{"FRONT_END_URL"},
	}
	serverHttpUrlFlag = &cli.StringFlag{
		Name:  "server-http-url",
		Value: "http://localhost:8080",
		Usage: "the url on which the http server is reachable from the outside",
	}
	sessionSecretFlag = &cli.StringFlag{
		Name:     "session-secret",
		Value:    "geheim",
		Usage:    "session secret encrypts the cookie, used by goth cookiestore",
		Required: true,
		EnvVars:  []string{"SESSION_SECRET"},
	}
	logLevelFlag = &cli.StringFlag{
		Name:  "log-level",
		Value: "info",
		Usage: "log-level can be one of error|warn|info|debug",
	}
	masterdataApiHostnameFlag = &cli.StringFlag{
		Name:  "masterdata-api-hostname",
		Value: "localhost",
		Usage: "masterdata-api hostname",
	}
	masterdataApiPortFlag = &cli.IntFlag{
		Name:  "masterdata-api-port",
		Value: 50051,
		Usage: "masterdata-api port",
	}
	masterdataApiHmacFlag = &cli.StringFlag{
		Name:  "masterdata-api-hmac",
		Value: "4Rahs0WnJ4rJE8ZiwiLec62z",
		Usage: "masterdata-api-hmac",
	}
	masterdataApiCAPathFlag = &cli.StringFlag{
		Name:  "masterdata-api-ca-path",
		Value: "certs/ca.pem",
		Usage: "masterdata-api CA path",
	}
	masterdataApiCertPathFlag = &cli.StringFlag{
		Name:  "masterdata-api-cert-path",
		Value: "certs/client.pem",
		Usage: "masterdata-api certificate path",
	}
	masterdataApiCertKeyPathFlag = &cli.StringFlag{
		Name:  "masterdata-api-cert-key-path",
		Value: "certs/client-key.pem",
		Usage: "masterdata-api certificate key path",
	}
	auditingUrlFlag = &cli.StringFlag{
		Name:  "auditing-url",
		Value: "http://localhost:7700",
		Usage: "url of the auditing service",
	}
	auditingApiKeyFlag = &cli.StringFlag{
		Name:  "auditing-api-key",
		Value: "geheim",
		Usage: "api key for the auditing service",
	}
	auditingEnabledFlag = &cli.BoolFlag{
		Name:  "auditing-enabled",
		Value: false,
		Usage: "enable auditing",
	}
	auditingIndexPrefixFlag = &cli.StringFlag{
		Name:  "auditing-index-prefix",
		Value: "auditing",
		Usage: "auditing index prefix",
	}
	auditingIndexIntervalFlag = &cli.StringFlag{
		Name:  "auditing-index-interval",
		Value: "@daily",
		Usage: "auditing index creation interval, can be one of @hourly|@daily|@monthly",
	}
	auditingIndexKeepFlag = &cli.Int64Flag{
		Name:  "auditing-index-keep",
		Value: 10,
		Usage: "auditing index retention, keep only the newest amount of indexes",
	}
	stageFlag = &cli.StringFlag{
		Name:    "stage",
		Value:   stagePROD,
		Usage:   "deployment stage of application",
		EnvVars: []string{"STAGE"},
	}
	redisAddrFlag = &cli.StringFlag{
		Name:    "redis-addr",
		Value:   "",
		Usage:   "the address to a redis key value store",
		EnvVars: []string{"REDIS_ADDR"},
	}
	redisPasswordFlag = &cli.StringFlag{
		Name:    "redis-password",
		Value:   "",
		Usage:   "the password to the redis key value store",
		EnvVars: []string{"REDIS_PASSWORD"},
	}
	adminOrgsFlag = &cli.StringSliceFlag{
		Name:  "admin-orgs",
		Value: cli.NewStringSlice("metal-stack-ops@github"),
		Usage: "the organizations that are considered as administrators when creating api tokens such that members gain extended api access permissions",
	}
	maxRequestsPerMinuteFlag = &cli.IntFlag{
		Name:  "max-requests-per-minute",
		Value: 100,
		Usage: "the maximum requests per minute per api token",
	}
	maxRequestsPerMinuteUnauthenticatedFlag = &cli.IntFlag{
		Name:  "max-unauthenticated-requests-per-minute",
		Value: 20,
		Usage: "the maximum requests per minute for unauthenticated api access",
	}
)

func main() {
	app := &cli.App{
		Name:  "api-server",
		Usage: "cli for metal cloud",
		Commands: []*cli.Command{
			serveCmd,
			tokenCmd,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("Error in cli: %v", err)
	}
}

func createLoggers(ctx *cli.Context) (*slog.Logger, slog.Level, error) {
	var (
		level  = slog.LevelInfo
		lvlvar slog.LevelVar
	)
	err := lvlvar.UnmarshalText([]byte(ctx.String(logLevelFlag.Name)))
	if err != nil {
		return nil, level, err
	}
	level = lvlvar.Level()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	return logger, level, nil
}
