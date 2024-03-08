package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/metal-stack/api-server/pkg/token"
	"github.com/redis/go-redis/v9"
)

const (
	prefix = "certstore_"
)

type Config struct {
	RedisClient               *redis.Client
	RenewCertBeforeExpiration *time.Duration
}

type CertStore interface {
	LatestPrivate(ctx context.Context) (*ecdsa.PrivateKey, error)
	PublicKeys(ctx context.Context) (jwk.Set, string, error)
}

type redisStore struct {
	client                    *redis.Client
	renewCertBeforeExpiration time.Duration
}

type privateKey struct {
	Serial    int64     `json:"serial"`
	Raw       []byte    `json:"raw"`
	ExpiresAt time.Time `json:"exp"`
}

func keyPublic() string {
	return prefix + "root_tokens_public_" + uuid.New().String()
}

func keyPrivateLatest() string {
	return prefix + "root_tokens_private"
}

func matchPublic() string {
	return prefix + "root_tokens_public_" + "*"
}

func NewRedisStore(c *Config) CertStore {
	renewCertBeforeExpiration := 90 * 24 * time.Hour
	if c.RenewCertBeforeExpiration != nil {
		renewCertBeforeExpiration = *c.RenewCertBeforeExpiration
	}
	return &redisStore{
		client:                    c.RedisClient,
		renewCertBeforeExpiration: renewCertBeforeExpiration,
	}
}

func (r *redisStore) LatestPrivate(ctx context.Context) (*ecdsa.PrivateKey, error) {
	res, err := r.client.Get(ctx, keyPrivateLatest()).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) { // this means not found
			return nil, err
		}

		return r.setNewCert(ctx)
	}

	var privateKey privateKey
	err = json.Unmarshal([]byte(res), &privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal private key: %w", err)
	}

	decoded, _ := pem.Decode(privateKey.Raw)
	if decoded == nil {
		return nil, fmt.Errorf("ecdsa private key is no valid pem block")
	}

	privKey, err := x509.ParseECPrivateKey(decoded.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}

	if time.Until(privateKey.ExpiresAt) < r.renewCertBeforeExpiration {
		return r.setNewCert(ctx)
	}

	return privKey, nil
}

func (r *redisStore) setNewCert(ctx context.Context) (*ecdsa.PrivateKey, error) {
	now := time.Now()

	cert, privKey, rawBytes, err := createRootCertificate("metal-stack", now, now.Add(2*token.MaxExpiration))
	if err != nil {
		return nil, fmt.Errorf("unable to create certificate: %w", err)
	}

	x509Key, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key: %w", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509Key,
	})

	expires := time.Until(cert.NotAfter)

	encoded, err := json.Marshal(&privateKey{
		Raw:       pemEncoded,
		ExpiresAt: cert.NotAfter,
		Serial:    cert.SerialNumber.Int64(),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to encode signing certificate: %w", err)
	}

	pipe := r.client.TxPipeline()

	_ = pipe.Set(ctx, keyPrivateLatest(), string(encoded), expires)
	_ = pipe.Set(ctx, keyPublic(), string(rawBytes), expires)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to store certificate: %w", err)
	}

	return privKey, nil
}

func (r *redisStore) PublicKeys(ctx context.Context) (jwk.Set, string, error) {
	var (
		set  = jwk.NewSet()
		iter = r.client.Scan(ctx, 0, matchPublic(), 0).Iterator()
	)

	for iter.Next(ctx) {
		pemEncoded, err := r.client.Get(ctx, iter.Val()).Result()
		if err != nil {
			return nil, "", err
		}

		decoded, _ := pem.Decode([]byte(pemEncoded))
		if decoded == nil {
			return nil, "", fmt.Errorf("is no valid pem block")
		}

		c, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return nil, "", err
		}

		key, err := jwk.FromRaw(c.PublicKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to add public key: %w", err)
		}

		err = set.AddKey(key)
		if err != nil {
			return nil, "", err
		}
	}
	if err := iter.Err(); err != nil {
		return nil, "", err
	}

	res, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("unable to marshal json: %w", err)
	}

	return set, string(res), nil
}

func createRootCertificate(org string, from, to time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to generate ecdsa key: %w", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMilli()),
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             from,
		NotAfter:              to,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to pem encode signing certificate: %w", err)
	}

	return cert, key, buf.Bytes(), nil

}
