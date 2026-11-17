// Package signing signs and verifies challenge packages and catalog indexes
// (D40). Signatures are Sigstore bundles stored as OCI referrers of the
// signed manifest; they are verified with sigstore-go against the
// TrustPolicy of the source.
//
// The signed content is the OCI manifest of the artifact. A bundle may hold a
// message signature over those bytes (what this package produces) or a DSSE
// envelope whose in-toto statement names the manifest digest.
package signing

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

// ErrUnsigned is returned when an artifact has no signature and the trust
// policy does not allow unsigned artifacts.
var ErrUnsigned = errors.New("the artifact is not signed")

// MaxSignatures bounds how many signatures of one artifact are examined.
const MaxSignatures = 16

// Verifier checks signatures against trust policies.
type Verifier struct {
	// TrustedRoot holds the Sigstore certificate authorities, transparency
	// logs and timestamp authorities trusted for keyless signatures. Nil
	// refuses keyless signatures.
	TrustedRoot root.TrustedMaterial
	// WithoutSCTs accepts certificates without a signed certificate
	// timestamp, for private Sigstore deployments without a certificate
	// transparency log. The public-good Fulcio always embeds one.
	WithoutSCTs bool
}

// Verify checks that one of bundles signs artifact (the OCI manifest bytes)
// for a signer accepted by trust, and returns that signer: the certificate
// identity for keyless signatures, the key fingerprint otherwise. With
// trust.AllowUnsigned, an artifact without a valid signature is accepted
// with an empty signer.
func (v Verifier) Verify(trust v1alpha1.TrustPolicy, artifact []byte, bundles [][]byte) (string, error) {
	var errs []error
	for i, raw := range bundles {
		if i == MaxSignatures {
			errs = append(errs, fmt.Errorf("only the first %d signatures are examined", MaxSignatures))
			break
		}
		signer, err := v.verifyBundle(trust, artifact, raw)
		if err == nil {
			return signer, nil
		}
		errs = append(errs, fmt.Errorf("signature %d: %w", i+1, err))
	}
	switch {
	case trust.AllowUnsigned:
		return "", nil
	case len(bundles) == 0:
		return "", ErrUnsigned
	default:
		return "", fmt.Errorf("no signature matches the trust policy: %w", errors.Join(errs...))
	}
}

func (v Verifier) verifyBundle(trust v1alpha1.TrustPolicy, artifact, raw []byte) (string, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return "", fmt.Errorf("decoding the bundle: %w", err)
	}
	return v.verifyEntity(trust, artifact, &b)
}

func (v Verifier) verifyEntity(trust v1alpha1.TrustPolicy, artifact []byte, entity verify.SignedEntity) (string, error) {
	content, err := entity.VerificationContent()
	if err != nil {
		return "", err
	}
	if content.Certificate() != nil {
		return v.verifyKeyless(trust.Keyless, artifact, entity)
	}
	return verifyKey(trust.Keys, artifact, entity)
}

// verifyKeyless accepts a Fulcio certificate matching one of the identities,
// logged in a transparency log and timestamped while it was valid.
func (v Verifier) verifyKeyless(identities []v1alpha1.KeylessIdentity, artifact []byte, b verify.SignedEntity) (string, error) {
	if len(identities) == 0 {
		return "", errors.New("signed with a certificate, but the trust policy lists no keyless identity")
	}
	if v.TrustedRoot == nil {
		return "", errors.New("no Sigstore trusted root to verify keyless signatures")
	}
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if !v.WithoutSCTs {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	verifier, err := verify.NewVerifier(v.TrustedRoot, opts...)
	if err != nil {
		return "", err
	}
	var errs []error
	for _, id := range identities {
		certID, err := verify.NewShortCertificateIdentity(id.Issuer, "", "", id.SubjectRegExp)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		res, err := verifier.Verify(b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifact)), verify.WithCertificateIdentity(certID)))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cert := res.Signature.Certificate
		return fmt.Sprintf("%s (%s)", cert.SubjectAlternativeName, cert.Issuer), nil
	}
	return "", errors.Join(errs...)
}

// verifyKey accepts a signature made by one of keys (PEM public keys). Key
// signatures need no transparency log: they are checked at the current time.
func verifyKey(keys []string, artifact []byte, b verify.SignedEntity) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("signed with a key, but the trust policy lists no key")
	}
	var errs []error
	for i, pemKey := range keys {
		pub, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pemKey))
		if err != nil {
			errs = append(errs, fmt.Errorf("trusted key %d: %w", i+1, err))
			continue
		}
		sv, err := sigsig.LoadVerifier(pub, crypto.SHA256)
		if err != nil {
			errs = append(errs, fmt.Errorf("trusted key %d: %w", i+1, err))
			continue
		}
		// One key at a time, whatever hint the bundle carries.
		material := root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
			return root.NewExpiringKey(sv, timeZero, timeZero), nil
		})
		verifier, err := verify.NewVerifier(material, verify.WithCurrentTime())
		if err != nil {
			return "", err
		}
		if _, err := verifier.Verify(b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifact)), verify.WithKey())); err != nil {
			errs = append(errs, fmt.Errorf("trusted key %d: %w", i+1, err))
			continue
		}
		fingerprint, err := KeyFingerprint(pub)
		if err != nil {
			return "", err
		}
		return "key " + fingerprint, nil
	}
	return "", errors.Join(errs...)
}

// KeyFingerprint identifies a public key: "sha256:<hex>" of its PKIX DER form.
func KeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := cryptoutils.MarshalPublicKeyToDER(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
