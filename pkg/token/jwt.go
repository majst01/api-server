package token

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	v1 "github.com/metal-stack/api/go/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	DefaultExpiration = time.Hour * 8
	MaxExpiration     = 365 * 24 * time.Hour
)

type (
	// MethodPermissions is a map from project or organization ->[]methods, e.g.: "/api.v1.ClusterService/List"
	MethodPermissions map[string][]string
	// TokenRoles maps the role to subject
	// subject can be either * (Wildcard) or the concrete Organization or Project
	// role can be one of admin, owner, editor, viewer
	TokenRoles map[string]string
	Claims     struct {
		jwt.RegisteredClaims

		Roles       TokenRoles        `json:"roles,omitempty"`
		Permissions MethodPermissions `json:"permissions,omitempty"`
		Type        string            `json:"type"`
	}

	tokenClaimsContextKey struct{}
)

func NewJWT(tokenType v1.TokenType, subject, issuer string, roles []*v1.TokenRole, projectPermissions []*v1.MethodPermission, expires time.Duration, secret crypto.PrivateKey) (string, *v1.Token, error) {
	if expires == 0 {
		expires = DefaultExpiration
	}
	if expires > MaxExpiration {
		return "", nil, fmt.Errorf("expires:%q exceeds maximum:%q", expires, MaxExpiration)
	}

	pp := MethodPermissions{}

	for _, p := range projectPermissions {
		pp[p.Subject] = p.Methods
	}

	tr := TokenRoles{}

	for _, r := range roles {
		tr[r.Subject] = r.Role
	}

	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(expires)
	claims := &Claims{
		// see overview of "registered" JWT claims as used by jwt-go here:
		//   https://pkg.go.dev/github.com/golang-jwt/jwt/v4?utm_source=godoc#RegisteredClaims
		// see the semantics of the registered claims here:
		//   https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),

			// ID is for your traceability, doesn't have to be UUID:
			ID: uuid.New().String(),

			// put name/title/ID of whoever will be using this JWT here:
			Subject: subject,
			Issuer:  issuer,
		},
		Permissions: pp,
		Roles:       tr,
		Type:        tokenType.String(),
	}

	jwtWithClaims := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	res, err := jwtWithClaims.SignedString(secret)
	if err != nil {
		return "", nil, fmt.Errorf("unable to sign ES512 JWT: %w", err)
	}

	token := &v1.Token{
		Uuid:        claims.RegisteredClaims.ID,
		UserId:      subject,
		Permissions: projectPermissions,
		Roles:       roles,
		Expires:     timestamppb.New(expiresAt),
		IssuedAt:    timestamppb.New(issuedAt),
		TokenType:   tokenType,
	}

	return res, token, nil
}

// ParseJWTToken unverified to Claims to get Issuer,Subject, Roles and Permissions
func ParseJWTToken(token string) (*Claims, error) {
	if token == "" {
		return nil, nil
	}

	claims := &Claims{}
	_, _, err := new(jwt.Parser).ParseUnverified(string(token), claims)

	if err != nil {
		return nil, err
	}

	return claims, nil
}

// ContextWithTokenClaims stores the Claims in the Context
// Can later retrieved with TokenClaimsFromContext
func ContextWithTokenClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, tokenClaimsContextKey{}, claims)
}

// TokenClaimsFromContext retrieves the token claims and ok from the context
// if previously stored by calling ContextWithTokenClaims.
func TokenClaimsFromContext(ctx context.Context) (*Claims, bool) {
	value := ctx.Value(tokenClaimsContextKey{})

	tokenClaims, ok := value.(*Claims)
	return tokenClaims, ok
}
