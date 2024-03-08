package health

import (
	"context"
	"errors"
	"fmt"

	v1 "github.com/metal-stack/api/go/api/v1"
	metalgo "github.com/metal-stack/metal-go"
	metalhealth "github.com/metal-stack/metal-go/api/client/health"
	"github.com/metal-stack/metal-go/api/models"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/metal-stack/metal-lib/rest"
)

type machineHealthChecker struct {
	m metalgo.Client
}

func (h *machineHealthChecker) Health(ctx context.Context) *v1.HealthStatus {
	var healthResp *models.RestHealthResponse

	resp, err := h.m.Health().Health(metalhealth.NewHealthParams().WithContext(ctx), nil)
	if err != nil {
		var r *metalhealth.HealthInternalServerError
		if errors.As(err, &r) {
			healthResp = r.Payload
		} else {
			return &v1.HealthStatus{
				Name:    v1.Service_SERVICE_MACHINES,
				Status:  v1.ServiceStatus_SERVICE_STATUS_UNSPECIFIED,
				Message: fmt.Sprintf("unable to fetch metal-api health status: %s", err),
			}
		}
	} else {
		healthResp = resp.Payload
	}

	status := v1.ServiceStatus_SERVICE_STATUS_HEALTHY
	switch rest.HealthStatus(pointer.SafeDeref(healthResp.Status)) {
	case rest.HealthStatusHealthy:
		status = v1.ServiceStatus_SERVICE_STATUS_HEALTHY
	case rest.HealthStatusDegraded, rest.HealthStatusPartiallyUnhealthy:
		status = v1.ServiceStatus_SERVICE_STATUS_DEGRADED
	case rest.HealthStatusUnhealthy:
		status = v1.ServiceStatus_SERVICE_STATUS_UNHEALTHY
	}

	return &v1.HealthStatus{
		Name:    v1.Service_SERVICE_MACHINES,
		Status:  status,
		Message: pointer.SafeDeref(pointer.SafeDeref(healthResp).Message),
	}
}
