package auth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/metal-stack/api-server/pkg/certs"
	putil "github.com/metal-stack/api-server/pkg/project"
	tokenservice "github.com/metal-stack/api-server/pkg/service/token"
	"github.com/metal-stack/api-server/pkg/token"
	v1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func Test_opa_cert_rotation(t *testing.T) {
	oldMaxExpiration := token.MaxExpiration
	oldDefaultExpiration := token.DefaultExpiration

	token.MaxExpiration = 5 * time.Second
	token.DefaultExpiration = 5 * time.Second
	defer func() {
		token.MaxExpiration = oldMaxExpiration
		token.DefaultExpiration = oldDefaultExpiration
	}()
	renewCertBeforeExpiration := 7 * time.Second

	t.Logf("token lifetime: %s, certificate lifetime: %s, issue new signing certificate after: %s", token.DefaultExpiration, 2*token.MaxExpiration, 2*token.MaxExpiration-renewCertBeforeExpiration)

	var (
		s   = miniredis.RunT(t)
		c   = redis.NewClient(&redis.Options{Addr: s.Addr()})
		log = slog.Default()

		certStore = certs.NewRedisStore(&certs.Config{
			RedisClient:               c,
			RenewCertBeforeExpiration: &renewCertBeforeExpiration,
		})
		tokenStore = token.NewRedisStore(c)

		opa = func() *opa {
			o, err := New(Config{
				Log:            log,
				CertStore:      certStore,
				CertCacheTime:  pointer.Pointer(0 * time.Second),
				TokenStore:     tokenStore,
				MasterClient:   nil,
				AllowedIssuers: []string{"integration"},
			})
			require.NoError(t, err)

			o.projectsAndTenantsGetter = func(ctx context.Context, userId string) (*putil.ProjectsAndTenants, error) {
				return &putil.ProjectsAndTenants{
					ProjectRoles: map[string]v1.ProjectRole{
						"test-project": v1.ProjectRole_PROJECT_ROLE_VIEWER,
					},
				}, nil
			}

			return o
		}()

		ctx     = context.Background()
		service = func() tokenservice.TokenService {
			s := tokenservice.New(tokenservice.Config{
				Log:           log,
				CertStore:     certStore,
				TokenStore:    tokenStore,
				MasterClient:  nil,
				AdminSubjects: []string{},
				Issuer:        "integration",
			})

			return s
		}()

		token1 = ""
		token2 = ""
		token3 = ""

		wg sync.WaitGroup

		steps = []struct {
			name string
			at   time.Duration
			task func(t *testing.T)
		}{
			{
				name: "token 1",
				at:   0 * time.Second,
				task: func(t *testing.T) {
					token1 = createNewConsoleToken(t, ctx, service)
					expectCertStore(t, ctx, certStore, 1)
					expectTokenWorks(t, ctx, opa, token1)
				},
			},
			{
				name: "token2",
				at:   2 * time.Second,
				task: func(t *testing.T) {
					token2 = createNewConsoleToken(t, ctx, service)
					expectCertStore(t, ctx, certStore, 1)
					expectTokenWorks(t, ctx, opa, token1)
					expectTokenWorks(t, ctx, opa, token2)
				},
			},
			{
				name: "token3, next signing cert gets created",
				at:   4 * time.Second,
				task: func(t *testing.T) {
					token3 = createNewConsoleToken(t, ctx, service)
					expectCertStore(t, ctx, certStore, 2)
					expectTokenWorks(t, ctx, opa, token1)
					expectTokenWorks(t, ctx, opa, token2)
					expectTokenWorks(t, ctx, opa, token3)
				},
			},
			{
				name: "token1 expired, token 2 and 3 still work",
				at:   6 * time.Second,
				task: func(t *testing.T) {
					token3 = createNewConsoleToken(t, ctx, service)
					expectCertStore(t, ctx, certStore, 2)
					expectTokenExpired(t, ctx, opa, token1)
					expectTokenWorks(t, ctx, opa, token2)
					expectTokenWorks(t, ctx, opa, token3)
				},
			},
			{
				name: "token1 and token2 expired, token 3 still works",
				at:   8 * time.Second,
				task: func(t *testing.T) {
					expectCertStore(t, ctx, certStore, 2)
					expectTokenExpired(t, ctx, opa, token1)
					expectTokenExpired(t, ctx, opa, token2)
					expectTokenWorks(t, ctx, opa, token3)
				},
			},
			{
				name: "all tokens expired, first signing cert is gone",
				at:   11 * time.Second,
				task: func(t *testing.T) {
					expectCertStore(t, ctx, certStore, 1)
					expectTokenExpired(t, ctx, opa, token1)
					expectTokenExpired(t, ctx, opa, token2)
					expectTokenExpired(t, ctx, opa, token3)
				},
			},
			{
				name: "all tokens expired, all signing certs gone",
				at:   15 * time.Second,
				task: func(t *testing.T) {
					expectCertStore(t, ctx, certStore, 0)
					expectTokenExpired(t, ctx, opa, token1)
					expectTokenExpired(t, ctx, opa, token2)
					expectTokenExpired(t, ctx, opa, token3)
				},
			},
		}
	)

	var (
		start      = time.Now().Add(1 * time.Second)
		previousAt *time.Duration
		mtx        sync.Mutex
	)

	for _, step := range steps {
		step := step

		wg.Add(1)

		go t.Run(step.name, func(t *testing.T) {
			defer wg.Done()

			childCtx, cancel := context.WithDeadline(ctx, start.Add(step.at))
			defer cancel()

			<-childCtx.Done()

			mtx.Lock()
			defer mtx.Unlock()

			forwardText := ""
			if previousAt != nil {
				forward := step.at - *previousAt
				forwardText = fmt.Sprintf(" (forwarding redis by %s)", forward)
				s.FastForward(forward)
			}
			previousAt = &step.at

			t.Logf("%s: running step at %q%s: %q", time.Now(), step.at, forwardText, step.name)

			step.task(t)
		})
	}

	wg.Wait()
}

func createNewConsoleToken(t *testing.T, ctx context.Context, service tokenservice.TokenService) string {
	resp, err := service.CreateConsoleTokenWithoutPermissionCheck(ctx, "test-user", nil)
	require.NoError(t, err)

	return resp.Msg.Secret
}

func expectTokenWorks(t *testing.T, ctx context.Context, opa *opa, bearer string) {
	err := checkToken(ctx, opa, bearer)
	require.NoError(t, err)
}

func expectTokenExpired(t *testing.T, ctx context.Context, opa *opa, bearer string) {
	err := checkToken(ctx, opa, bearer)
	require.Error(t, err)
	require.ErrorContains(t, err, "unauthenticated: token has expired")
}

func checkToken(ctx context.Context, opa *opa, bearer string) error {
	jwtTokenFunc := func(_ string) string {
		return "Bearer " + bearer
	}

	_, err := opa.decide(ctx, "/metalstack.api.v1.IPService/Get", jwtTokenFunc, v1.IPServiceGetRequest{
		Project: "test-project",
	})

	return err
}

func expectCertStore(t *testing.T, ctx context.Context, c certs.CertStore, publicKeyAmount int) {
	_, rawSet, err := c.PublicKeys(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, rawSet)

	set, err := jwk.ParseString(rawSet)
	require.NoError(t, err)
	require.Equal(t, publicKeyAmount, set.Len())
}
