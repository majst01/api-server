package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/metal-stack/api-server/pkg/certs"
	"github.com/metal-stack/api-server/pkg/service/token"
	tokencommon "github.com/metal-stack/api-server/pkg/token"
	apiv1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/urfave/cli/v2"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	tokenDescriptionFlag = &cli.StringFlag{
		Name:  "description",
		Value: "",
		Usage: "the description for what this token is going to be used",
	}
	tokenPermissionsFlag = &cli.StringSliceFlag{
		Name:  "permissions",
		Value: &cli.StringSlice{},
		Usage: "requested permissions for the token",
	}
	tokenProjectRolesFlag = &cli.StringSliceFlag{
		Name:  "project-roles",
		Value: &cli.StringSlice{},
		Usage: "requested project roles for the token",
	}
	tokenTenantRolesFlag = &cli.StringSliceFlag{
		Name:  "tenant-roles",
		Value: &cli.StringSlice{},
		Usage: "requested tenant roles for the token",
	}
	tokenAdminRoleFlag = &cli.StringFlag{
		Name:  "admin-role",
		Value: "",
		Usage: "requested admin role for the token",
	}
	tokenExpirationFlag = &cli.DurationFlag{
		Name:  "expiration",
		Value: 6 * 30 * 24 * time.Hour,
		Usage: "requested expiration for the token",
	}
)

var tokenCmd = &cli.Command{
	Name:  "token",
	Usage: "create api tokens for cloud infrastructure services that depend on the api-server like accounting, status dashboard, ...",
	Flags: []cli.Flag{
		logLevelFlag,
		redisAddrFlag,
		redisPasswordFlag,
		tokenDescriptionFlag,
		tokenPermissionsFlag,
		tokenProjectRolesFlag,
		tokenTenantRolesFlag,
		tokenAdminRoleFlag,
		tokenExpirationFlag,
		serverHttpUrlFlag,
	},
	Action: func(ctx *cli.Context) error {
		log, _, err := createLoggers(ctx)
		if err != nil {
			return fmt.Errorf("unable to create logger %w", err)
		}

		tokenRedisClient, err := createRedisClient(log, ctx.String(redisAddrFlag.Name), ctx.String(redisPasswordFlag.Name), redisDatabaseTokens)
		if err != nil {
			return err
		}

		tokenStore := tokencommon.NewRedisStore(tokenRedisClient)
		certStore := certs.NewRedisStore(&certs.Config{
			RedisClient: tokenRedisClient,
		})

		tokenService := token.New(token.Config{
			Log:        log,
			TokenStore: tokenStore,
			CertStore:  certStore,
			Issuer:     ctx.String(serverHttpUrlFlag.Name),
		})

		var permissions []*apiv1.MethodPermission
		for _, m := range ctx.StringSlice(tokenPermissionsFlag.Name) {
			project, semicolonSeparatedMethods, ok := strings.Cut(m, "=")
			if !ok {
				return fmt.Errorf("permissions must be provided in the form <project>=<methods-colon-separated>")
			}

			permissions = append(permissions, &apiv1.MethodPermission{
				Subject: project,
				Methods: strings.Split(semicolonSeparatedMethods, ":"),
			})
		}

		projectRoles := map[string]apiv1.ProjectRole{}
		for _, r := range ctx.StringSlice(tokenProjectRolesFlag.Name) {
			projectID, roleString, ok := strings.Cut(r, "=")
			if !ok {
				return fmt.Errorf("project roles must be provided in the form <project-id>=<role>")
			}

			role, ok := apiv1.ProjectRole_value[roleString]
			if !ok {
				return fmt.Errorf("unknown role: %s", roleString)
			}

			projectRoles[projectID] = apiv1.ProjectRole(role)
		}

		tenantRoles := map[string]apiv1.TenantRole{}
		for _, r := range ctx.StringSlice(tokenTenantRolesFlag.Name) {
			tenantID, roleString, ok := strings.Cut(r, "=")
			if !ok {
				return fmt.Errorf("tenant roles must be provided in the form <tenant-id>=<role>")
			}

			role, ok := apiv1.TenantRole_value[roleString]
			if !ok {
				return fmt.Errorf("unknown role: %s", roleString)
			}

			tenantRoles[tenantID] = apiv1.TenantRole(role)
		}

		var adminRole *apiv1.AdminRole
		if roleString := ctx.String(tokenAdminRoleFlag.Name); roleString != "" {
			role, ok := apiv1.AdminRole_value[roleString]
			if !ok {
				return fmt.Errorf("unknown role: %s", roleString)
			}

			adminRole = pointer.Pointer(apiv1.AdminRole(role))
		}

		resp, err := tokenService.CreateApiTokenWithoutPermissionCheck(context.Background(), connect.NewRequest(&apiv1.TokenServiceCreateRequest{
			Description:  ctx.String(tokenDescriptionFlag.Name),
			Expires:      durationpb.New(ctx.Duration(tokenExpirationFlag.Name)),
			ProjectRoles: projectRoles,
			TenantRoles:  tenantRoles,
			AdminRole:    adminRole,
			Permissions:  permissions,
		}))
		if err != nil {
			return err
		}

		fmt.Println(resp.Msg.Secret)

		return nil
	},
}
