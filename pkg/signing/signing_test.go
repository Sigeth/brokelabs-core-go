package signing

import (
	"context"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

var artifact = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)

func keySigned(t *testing.T) (*KeyPair, string, []byte) {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.GetPublicKeyPem()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(artifact, kp, sign.BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return kp, pub, b
}

func TestKeySignatures(t *testing.T) {
	kp, pub, b := keySigned(t)
	_, otherPub, _ := keySigned(t)
	fingerprint, _ := KeyFingerprint(kp.GetPublicKey())

	signer, err := Verifier{}.Verify(v1alpha1.TrustPolicy{Keys: []string{otherPub, pub}}, artifact, [][]byte{b})
	if err != nil || signer != "key "+fingerprint {
		t.Fatalf("signer = %q, %v", signer, err)
	}

	cases := map[string]struct {
		trust    v1alpha1.TrustPolicy
		artifact []byte
		bundles  [][]byte
		want     string
	}{
		"another key":         {v1alpha1.TrustPolicy{Keys: []string{otherPub}}, artifact, [][]byte{b}, "no signature matches"},
		"tampered artifact":   {v1alpha1.TrustPolicy{Keys: []string{pub}}, append([]byte(" "), artifact...), [][]byte{b}, "no signature matches"},
		"only keyless":        {v1alpha1.TrustPolicy{Keyless: []v1alpha1.KeylessIdentity{{Issuer: "x", SubjectRegExp: ".*"}}}, artifact, [][]byte{b}, "lists no key"},
		"not a bundle":        {v1alpha1.TrustPolicy{Keys: []string{pub}}, artifact, [][]byte{[]byte("{}")}, "bundle"},
		"no signature at all": {v1alpha1.TrustPolicy{Keys: []string{pub}}, artifact, nil, ErrUnsigned.Error()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			signer, err := Verifier{}.Verify(tc.trust, tc.artifact, tc.bundles)
			if err == nil || !strings.Contains(err.Error(), tc.want) || signer != "" {
				t.Fatalf("signer = %q, error = %v, want one containing %q", signer, err, tc.want)
			}
		})
	}
}

func TestAllowUnsigned(t *testing.T) {
	_, otherPub, _ := keySigned(t)
	_, _, b := keySigned(t)
	trust := v1alpha1.TrustPolicy{AllowUnsigned: true, Keys: []string{otherPub}}
	for _, bundles := range [][][]byte{nil, {b}} {
		if signer, err := (Verifier{}).Verify(trust, artifact, bundles); err != nil || signer != "" {
			t.Fatalf("signer = %q, %v", signer, err)
		}
	}
}

func TestTooManySignatures(t *testing.T) {
	_, pub, _ := keySigned(t)
	bundles := make([][]byte, MaxSignatures+1)
	for i := range bundles {
		bundles[i] = []byte("{}")
	}
	_, err := Verifier{}.Verify(v1alpha1.TrustPolicy{Keys: []string{pub}}, artifact, bundles)
	if err == nil || !strings.Contains(err.Error(), "only the first") {
		t.Fatalf("error = %v", err)
	}
}

func TestKeylessSignatures(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	const (
		issuer   = "https://token.actions.githubusercontent.com"
		identity = "https://github.com/Sigeth/brokelabs-challenges/.github/workflows/release.yaml@refs/tags/ssh-hardening/v1.0.0"
	)
	entity, err := vs.Sign(identity, issuer, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Verifier{TrustedRoot: vs}).verifyEntity(v1alpha1.TrustPolicy{Keyless: []v1alpha1.KeylessIdentity{
		{Issuer: issuer, SubjectRegExp: ".*"}}}, artifact, entity); err == nil || !strings.Contains(err.Error(), "certificate timestamp") {
		t.Fatalf("certificates without an SCT must be refused by default: %v", err)
	}
	v := Verifier{TrustedRoot: vs, WithoutSCTs: true} // the test CA has no CT log
	trusted := v1alpha1.TrustPolicy{Keyless: []v1alpha1.KeylessIdentity{
		{Issuer: issuer, SubjectRegExp: `^https://github\.com/Sigeth/brokelabs-challenges/\.github/workflows/release\.yaml@.*$`},
	}}
	signer, err := v.verifyEntity(trusted, artifact, entity)
	if err != nil || signer != identity+" ("+issuer+")" {
		t.Fatalf("signer = %q, %v", signer, err)
	}

	cases := map[string]struct {
		v     Verifier
		trust v1alpha1.TrustPolicy
		want  string
	}{
		"other repository": {v, v1alpha1.TrustPolicy{Keyless: []v1alpha1.KeylessIdentity{
			{Issuer: issuer, SubjectRegExp: `^https://github\.com/someone/else/.*$`}}}, "SAN"},
		"other issuer": {v, v1alpha1.TrustPolicy{Keyless: []v1alpha1.KeylessIdentity{
			{Issuer: "https://accounts.google.com", SubjectRegExp: ".*"}}}, "issuer"},
		"only keys":    {v, v1alpha1.TrustPolicy{Keys: []string{"unused"}}, "lists no keyless identity"},
		"no root":      {Verifier{}, trusted, "no Sigstore trusted root"},
		"another root": {Verifier{TrustedRoot: mustVirtualSigstore(t), WithoutSCTs: true}, trusted, "transparency log"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			signer, err := tc.v.verifyEntity(tc.trust, artifact, entity)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) || signer != "" {
				t.Fatalf("signer = %q, error = %v, want one containing %q", signer, err, tc.want)
			}
		})
	}
}

func mustVirtualSigstore(t *testing.T) *ca.VirtualSigstore {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

func TestAttachAndFetchBundles(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	subject := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, artifact)
	if err := store.Push(ctx, subject, strings.NewReader(string(artifact))); err != nil {
		t.Fatal(err)
	}
	_, _, b := keySigned(t)
	if _, err := Attach(ctx, store, subject, b); err != nil {
		t.Fatal(err)
	}
	bundles, err := Bundles(ctx, store, subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 || string(bundles[0]) != string(b) {
		t.Fatalf("bundles = %q", bundles)
	}

	other := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, []byte("{}"))
	if bundles, err := Bundles(ctx, store, other); err != nil || len(bundles) != 0 {
		t.Fatalf("bundles of an unsigned artifact = %q, %v", bundles, err)
	}
}

func TestLoadKeyPair(t *testing.T) {
	kp, _ := GenerateKeyPair()
	pemKey, err := kp.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeyPair(pemKey)
	if err != nil || string(loaded.GetHint()) != string(kp.GetHint()) {
		t.Fatalf("loaded = %v, %v", loaded, err)
	}
	if _, err := LoadKeyPair([]byte("not a key")); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := NewKeyPair("not a key"); err == nil {
		t.Fatal("expected an error")
	}
}
