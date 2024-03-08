package v1

import (
	"context"

	v1 "github.com/metal-stack/api/go/api/v1"
	mdcv1 "github.com/metal-stack/masterdata-api/api/v1"
)

type (
	projectAndTenant struct {
		p *mdcv1.Project
		t *mdcv1.Tenant
	}

	projectAndTenantKey struct{}
)

const (
	TagEmail     = "metal-stack.io/email"
	TagAvatarURL = "metal-stack.io/avatarurl"
	TagAdmitted  = "metal-stack.io/admitted"

	TagTermsAndConditions = "metal-stack.io/termsandconditions"
	TagEmailConsent       = "metal-stack.io/emailconsent"
	TagOnboarded          = "metal-stack.io/onboarded"

	TagOauthProvider = "metal-stack.io/oauth/provider"

	TagPaymentCustomerID = "metal-stack.io/payment/customerid"
	TagPaymentMethodID   = "metal-stack.io/payment/paymentmethodid"
	TagCoupons           = "metal-stack.io/payment/coupons"
	TagVat               = "metal-stack.io/payment/vat"
)

func Convert(t *v1.Tenant) *mdcv1.Tenant {
	ann := map[string]string{
		TagEmail:     t.Email,
		TagAvatarURL: t.AvatarUrl,
	}

	return &mdcv1.Tenant{
		Meta: &mdcv1.Meta{
			Id:          t.Login,
			Kind:        "Tenant",
			Annotations: ann,
		},
		Name: t.Name,
	}
}

func ConvertFromTenant(t *mdcv1.Tenant) *v1.Tenant {
	ann := t.Meta.Annotations
	email := ann[TagEmail]
	avatarURL := ann[TagAvatarURL]

	tenant := &v1.Tenant{
		Login:     t.Meta.Id,
		Name:      t.Name,
		Email:     email,
		AvatarUrl: avatarURL,
		CreatedAt: t.Meta.CreatedTime,
		UpdatedAt: t.Meta.UpdatedTime,
	}

	return tenant
}

// ContextWithProjectAndTenant stores project and tenant in the context
// this should be called early in a request interceptor.
func ContextWithProjectAndTenant(ctx context.Context, project *mdcv1.Project, tenant *mdcv1.Tenant) context.Context {
	return context.WithValue(ctx, projectAndTenantKey{}, projectAndTenant{p: project, t: tenant})
}

// ProjectAndTenantFromContext retrieves project and tenant and ok from the context
// if previously stored by calling ContextWithProjectAndTenant.
func ProjectAndTenantFromContext(ctx context.Context) (project *mdcv1.Project, tenant *mdcv1.Tenant, ok bool) {
	value := ctx.Value(projectAndTenantKey{})

	projectAndTenant, ok := value.(projectAndTenant)
	if ok {
		return projectAndTenant.p, projectAndTenant.t, true
	}
	return nil, nil, ok
}
