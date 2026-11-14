package signing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
)

// BundleMediaType is the media type of a Sigstore bundle, also used as the
// artifact type of the referrer holding it.
const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// MaxBundleSize bounds a downloaded bundle.
const MaxBundleSize = 64 << 10

// maxManifestSize bounds the manifest of a signature referrer.
const maxManifestSize = 16 << 10

// Attach stores bundle as a referrer of subject in dst and returns the
// descriptor of the referrer manifest.
func Attach(ctx context.Context, dst content.Pusher, subject ocispec.Descriptor, bundle []byte) (ocispec.Descriptor, error) {
	config := ocispec.DescriptorEmptyJSON
	layer := content.NewDescriptorFromBytes(BundleMediaType, bundle)
	manifest, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: BundleMediaType,
		Config:       config,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      &subject,
	})
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifest)
	desc.ArtifactType = BundleMediaType
	for _, blob := range []struct {
		desc ocispec.Descriptor
		data []byte
	}{{config, config.Data}, {layer, bundle}, {desc, manifest}} {
		if s, ok := dst.(content.ReadOnlyStorage); ok {
			if exists, err := s.Exists(ctx, blob.desc); err == nil && exists {
				continue
			}
		}
		if err := dst.Push(ctx, blob.desc, bytes.NewReader(blob.data)); err != nil {
			return ocispec.Descriptor{}, err
		}
	}
	return desc, nil
}

// Bundles returns the Sigstore bundles attached to subject in src (a remote
// repository, an OCI layout...), at most MaxSignatures + 1 (Verify reports
// when there are too many).
func Bundles(ctx context.Context, src content.ReadOnlyGraphStorage, subject ocispec.Descriptor) ([][]byte, error) {
	referrers, err := registry.Referrers(ctx, src, subject, BundleMediaType)
	if err != nil {
		return nil, fmt.Errorf("listing the signatures: %w", err)
	}
	if len(referrers) > MaxSignatures+1 {
		referrers = referrers[:MaxSignatures+1]
	}
	var bundles [][]byte
	for _, ref := range referrers {
		b, err := fetchBundle(ctx, src, ref)
		if err != nil {
			return nil, fmt.Errorf("signature %s: %w", ref.Digest, err)
		}
		bundles = append(bundles, b)
	}
	return bundles, nil
}

func fetchBundle(ctx context.Context, src content.Fetcher, desc ocispec.Descriptor) ([]byte, error) {
	if desc.MediaType != ocispec.MediaTypeImageManifest || desc.Size > maxManifestSize {
		return nil, fmt.Errorf("unexpected manifest (%s, %d bytes)", desc.MediaType, desc.Size)
	}
	data, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return nil, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	if manifest.ArtifactType != BundleMediaType || len(manifest.Layers) != 1 ||
		manifest.Layers[0].MediaType != BundleMediaType || manifest.Layers[0].Size > MaxBundleSize {
		return nil, fmt.Errorf("not a Sigstore bundle of at most %d bytes", MaxBundleSize)
	}
	return content.FetchAll(ctx, src, manifest.Layers[0])
}
