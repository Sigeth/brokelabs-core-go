package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
)

var timeZero time.Time

// KeyPair signs with an ECDSA P-256 key (sign.Keypair). Its hint is the key
// fingerprint.
type KeyPair struct {
	key  *ecdsa.PrivateKey
	hint []byte
}

var _ sign.Keypair = (*KeyPair)(nil)

// NewKeyPair wraps an ECDSA P-256 private key.
func NewKeyPair(key crypto.PrivateKey) (*KeyPair, error) {
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("signing keys must be ECDSA P-256")
	}
	fingerprint, err := KeyFingerprint(ec.Public())
	if err != nil {
		return nil, err
	}
	return &KeyPair{key: ec, hint: []byte(fingerprint)}, nil
}

// LoadKeyPair reads an unencrypted PEM private key (PKCS#8 or SEC 1), e.g.
// from "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256".
func LoadKeyPair(pemKey []byte) (*KeyPair, error) {
	key, err := cryptoutils.UnmarshalPEMToPrivateKey(pemKey, cryptoutils.SkipPassword)
	if err != nil {
		return nil, fmt.Errorf("reading the private key: %w", err)
	}
	return NewKeyPair(key)
}

// GenerateKeyPair creates a new P-256 key.
func GenerateKeyPair() (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewKeyPair(key)
}

// PrivateKeyPEM encodes the private key as PKCS#8 PEM.
func (k *KeyPair) PrivateKeyPEM() ([]byte, error) {
	return cryptoutils.MarshalPrivateKeyToPEM(k.key)
}

// GetHashAlgorithm implements sign.Keypair.
func (k *KeyPair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

// GetSigningAlgorithm implements sign.Keypair.
func (k *KeyPair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
}

// GetHint implements sign.Keypair.
func (k *KeyPair) GetHint() []byte { return k.hint }

// GetKeyAlgorithm implements sign.Keypair.
func (k *KeyPair) GetKeyAlgorithm() string { return "ECDSA" }

// GetPublicKey implements sign.Keypair.
func (k *KeyPair) GetPublicKey() crypto.PublicKey { return k.key.Public() }

// GetPublicKeyPem implements sign.Keypair.
func (k *KeyPair) GetPublicKeyPem() (string, error) {
	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(k.key.Public())
	return string(pemKey), err
}

// SignData implements sign.Keypair: it returns the signature and the digest.
func (k *KeyPair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	return sig, digest[:], err
}

// Sign signs artifact (the OCI manifest bytes) and returns the bundle as
// JSON. opts adds a certificate (keyless), transparency logs and timestamps;
// a key signature with zero opts is verified at the current time.
func Sign(artifact []byte, keypair sign.Keypair, opts sign.BundleOptions) ([]byte, error) {
	b, err := sign.Bundle(&sign.PlainData{Data: artifact}, keypair, opts)
	if err != nil {
		return nil, err
	}
	return protojson.Marshal(b)
}
