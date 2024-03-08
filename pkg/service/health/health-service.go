package health

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/metal-stack/api/go/api/v1"
	"github.com/metal-stack/api/go/api/v1/apiv1connect"
	"golang.org/x/sync/errgroup"
)

const (
	CheckerTimeout = 10 * time.Second
)

type healthchecker interface {
	Health(context.Context) *v1.HealthStatus
}

type Config struct {
	Log                 *slog.Logger
	Ctx                 context.Context
	HealthcheckInterval time.Duration
}

type healthServiceServer struct {
	log *slog.Logger

	checkers []healthchecker
	current  *v1.Health
}

func New(c Config) (apiv1connect.HealthServiceHandler, error) {
	var checkers []healthchecker
	h := &healthServiceServer{
		log: c.Log.WithGroup("healthService"),
		// initializing status with healthy at the start
		// --> at the beginning we always assume healthy state
		current:  newHealthyServiceMap(),
		checkers: checkers,
	}

	go h.fetchStatuses(c.Ctx, c.HealthcheckInterval)

	return h, nil
}

func (h *healthServiceServer) Get(ctx context.Context, rq *connect.Request[v1.HealthServiceGetRequest]) (*connect.Response[v1.HealthServiceGetResponse], error) {
	return connect.NewResponse(&v1.HealthServiceGetResponse{
		Health: h.current,
	}), nil
}

func (h *healthServiceServer) fetchStatuses(ctx context.Context, interval time.Duration) {
	err := h.updateStatuses(ctx)
	if err != nil {
		h.log.Error("service statuses cannot be fetched, status not updated", "error", err)
	}

	var (
		lastUpdate = time.Now()
		ticker     = time.NewTicker(interval)
	)

	for {
		select {
		case <-ticker.C:
			if time.Since(lastUpdate) < CheckerTimeout {
				h.log.Info("skip updating health status because last update was happening lately")
				continue
			}

			err := h.updateStatuses(ctx)
			if err != nil {
				h.log.Error("service statuses cannot be fetched, status not updated", "error", err)
			}

			lastUpdate = time.Now()

		case <-ctx.Done():
			h.log.Info("stopping health service status fetching")
			ticker.Stop()
			return
		}
	}
}

func (h *healthServiceServer) updateStatuses(outerCtx context.Context) error {
	var (
		statuses        = &v1.Health{}
		ctx, cancel     = context.WithTimeout(outerCtx, CheckerTimeout)
		group, groupCtx = errgroup.WithContext(ctx)
		resultChan      = make(chan *v1.HealthStatus)
		once            sync.Once
	)

	defer cancel()
	defer once.Do(func() { close(resultChan) })

	for _, checker := range h.checkers {
		if checker == nil {
			continue
		}

		checker := checker

		group.Go(func() error {
			resultChan <- checker.Health(groupCtx)
			return nil
		})
	}

	finished := make(chan bool)
	go func() {
		for r := range resultChan {
			r := r
			statuses.Services = append(statuses.Services, r)
		}

		finished <- true
	}()

	if err := group.Wait(); err != nil {
		return err
	}

	once.Do(func() { close(resultChan) })

	<-finished

	sort.Slice(statuses.Services, func(i, j int) bool {
		return statuses.Services[i].Name < statuses.Services[j].Name
	})

	h.current = statuses

	h.log.Info("health statuses checked successfully")

	return nil
}

func newHealthyServiceMap() *v1.Health {
	h := &v1.Health{}
	for i := range v1.Service_name {
		if i == 0 {
			// skipping unspecified
			continue
		}
		h.Services = append(h.Services, &v1.HealthStatus{
			Name:    v1.Service(i),
			Status:  v1.ServiceStatus_SERVICE_STATUS_HEALTHY,
			Message: "",
		})
	}

	sort.Slice(h.Services, func(i, j int) bool {
		return h.Services[i].Name < h.Services[j].Name
	})

	return h
}
