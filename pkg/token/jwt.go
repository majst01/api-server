package token

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	v1 "github.com/metal-stack/api/go/metalstack/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	DefaultExpiration = time.Hour * 8
	MaxExpiration     = 365 * 24 * time.Hour
)

type (
	Claims struct {
		jwt.RegisteredClaims

		Type string `json:"type"`
	}

	tokenContextKey struct{}
)

func NewJWT(tokenType v1.TokenType, subject, issuer string, expires time.Duration, secret crypto.PrivateKey) (string, *v1.Token, error) {
	if expires == 0 {
		expires = DefaultExpiration
	}
	if expires > MaxExpiration {
		return "", nil, fmt.Errorf("expires:%q exceeds maximum:%q", expires, MaxExpiration)
	}

	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(expires)
	claims := &Claims{
		// see overview of "registered" JWT claims as used by jwt-go here:
		//   https://pkg.go.dev/github.com/golang-jwt/jwt/v5?utm_source=godoc#RegisteredClaims
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
		Type: tokenType.String(),
	}

	jwtWithClaims := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	res, err := jwtWithClaims.SignedString(secret)
	if err != nil {
		return "", nil, fmt.Errorf("unable to sign ES512 JWT: %w", err)
	}

	token := &v1.Token{
		Uuid:      claims.RegisteredClaims.ID,
		UserId:    subject,
		Expires:   timestamppb.New(expiresAt),
		IssuedAt:  timestamppb.New(issuedAt),
		TokenType: tokenType,
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

// ContextWithToken stores the token in the Context
// Can later retrieved with TokenFromContext
func ContextWithToken(ctx context.Context, token *v1.Token) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

// TokenFromContext retrieves the token and ok from the context
// if previously stored by calling ContextWithToken.
func TokenFromContext(ctx context.Context) (*v1.Token, bool) {
	value := ctx.Value(tokenContextKey{})

	token, ok := value.(*v1.Token)

	return token, ok
}
