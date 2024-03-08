package v1

import (
	"context"
	"testing"

	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
	"github.com/stretchr/testify/assert"
)

func TestProjectAndTenantFromContext(t *testing.T) {
	ctx := context.Background()

	project := &mdcv1.Project{
		Name: "P1",
	}
	tenant := &mdcv1.Tenant{
		Name: "T1",
	}

	ctx = ContextWithProjectAndTenant(ctx, project, tenant)

	proj, ten, ok := ProjectAndTenantFromContext(ctx)
	assert.True(t, ok)
	assert.NotNil(t, proj)
	assert.NotNil(t, ten)
	assert.Equal(t, "P1", proj.Name)
	assert.Equal(t, "T1", ten.Name)

	newCtx := context.Background()
	proj, ten, ok = ProjectAndTenantFromContext(newCtx)
	assert.False(t, ok)
	assert.Nil(t, proj)
	assert.Nil(t, ten)
}
