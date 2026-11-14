// Package ocipkg stores challenge packages as OCI artifacts (D38).
//
// A package is an OCI image manifest with the artifact type ArtifactType. Its
// config blob is the manifest (challenge.yaml) as JSON, and its only layer is
// a reproducible tar+gzip archive of the package files. A solution is a second
// artifact whose subject is the package, so registries list it through the
// referrers API.
package ocipkg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
	"github.com/Sigeth/opslab-core-go/pkg/project"
)

// Media and artifact types.
var (
	// ArtifactType identifies a challenge package.
	ArtifactType = "application/vnd." + project.Name + ".challenge.v1"
	// SolutionArtifactType identifies the solution of a package.
	SolutionArtifactType = "application/vnd." + project.Name + ".challenge.solution.v1"
	// ConfigMediaType is the media type of the config blob: the manifest as JSON.
	ConfigMediaType = "application/vnd." + project.Name + ".challenge.config.v1+json"
	// FilesMediaType is the media type of the layer holding the package files.
	FilesMediaType = "application/vnd." + project.Name + ".challenge.files.v1.tar+gzip"
)

// Size limits checked before anything is downloaded.
const (
	// MaxConfigSize bounds the config blob.
	MaxConfigSize = 1 << 20
	// MaxLayerSize bounds the compressed files layer. The decompressed files
	// are bounded by challenge.MaxBundleSize.
	MaxLayerSize = 2 * challenge.MaxBundleSize
	// MaxManifestSize bounds the OCI manifest.
	MaxManifestSize = 64 << 10
)

// Package is a challenge package read from an OCI artifact.
type Package struct {
	// Descriptor of the OCI manifest: its digest identifies the package.
	Descriptor ocispec.Descriptor
	// Manifest is the challenge manifest, as stored (not defaulted).
	Manifest *v1alpha1.ChallengePackage
	// Files of the package by path, without the manifest file.
	Files map[string][]byte
}

// Pack stores a package in dst and returns the descriptor of its OCI
// manifest. files is a bundle (challenge.Bundle); its manifest file is left
// out, since the config blob holds the manifest. The same inputs always give
// the same digest.
func Pack(ctx context.Context, dst content.Pusher, pkg *v1alpha1.ChallengePackage, files map[string][]byte) (ocispec.Descriptor, error) {
	config, err := json.Marshal(pkg)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	annotations := map[string]string{
		ocispec.AnnotationTitle:   pkg.Metadata.Name,
		ocispec.AnnotationVersion: pkg.Metadata.Version,
	}
	return packArtifact(ctx, dst, ArtifactType, ConfigMediaType, config, files, nil, annotations)
}

// PackSolution stores the solution files of the package described by subject
// in dst and returns the descriptor of its OCI manifest.
func PackSolution(ctx context.Context, dst content.Pusher, subject ocispec.Descriptor, files map[string][]byte) (ocispec.Descriptor, error) {
	if len(files) == 0 {
		return ocispec.Descriptor{}, errors.New("the solution has no files")
	}
	return packArtifact(ctx, dst, SolutionArtifactType, ocispec.MediaTypeEmptyJSON, ocispec.DescriptorEmptyJSON.Data, files, &subject, nil)
}

func packArtifact(ctx context.Context, dst content.Pusher, artifactType, configType string, config []byte,
	files map[string][]byte, subject *ocispec.Descriptor, annotations map[string]string) (ocispec.Descriptor, error) {
	layer, err := archive(files)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	configDesc := content.NewDescriptorFromBytes(configType, config)
	layerDesc := content.NewDescriptorFromBytes(FilesMediaType, layer)
	manifest, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       configDesc,
		Layers:       []ocispec.Descriptor{layerDesc},
		Subject:      subject,
		Annotations:  annotations,
	})
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	manifestDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifest)
	manifestDesc.ArtifactType = artifactType
	manifestDesc.Annotations = annotations
	for _, blob := range []struct {
		desc ocispec.Descriptor
		data []byte
	}{{configDesc, config}, {layerDesc, layer}, {manifestDesc, manifest}} {
		if err := pushIfMissing(ctx, dst, blob.desc, blob.data); err != nil {
			return ocispec.Descriptor{}, err
		}
	}
	return manifestDesc, nil
}

func pushIfMissing(ctx context.Context, dst content.Pusher, desc ocispec.Descriptor, data []byte) error {
	if s, ok := dst.(content.ReadOnlyStorage); ok {
		if exists, err := s.Exists(ctx, desc); err == nil && exists {
			return nil
		}
	}
	return dst.Push(ctx, desc, bytes.NewReader(data))
}

// Fetch reads the package whose OCI manifest is desc from src. Sizes, media
// types, digests and file paths are checked; the manifest is decoded strictly
// but not validated (see challenge.Validate).
func Fetch(ctx context.Context, src content.Fetcher, desc ocispec.Descriptor) (*Package, error) {
	manifest, err := fetchManifest(ctx, src, desc, ArtifactType)
	if err != nil {
		return nil, err
	}
	if manifest.Config.MediaType != ConfigMediaType {
		return nil, fmt.Errorf("config has media type %q, want %q", manifest.Config.MediaType, ConfigMediaType)
	}
	config, err := fetchBlob(ctx, src, manifest.Config, MaxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	pkg, err := challenge.Parse(config)
	if err != nil {
		return nil, err
	}
	files, err := fetchFiles(ctx, src, manifest)
	if err != nil {
		return nil, err
	}
	return &Package{Descriptor: desc, Manifest: pkg, Files: files}, nil
}

// FetchSolution reads the solution files whose OCI manifest is desc from src.
func FetchSolution(ctx context.Context, src content.Fetcher, desc ocispec.Descriptor) (map[string][]byte, error) {
	manifest, err := fetchManifest(ctx, src, desc, SolutionArtifactType)
	if err != nil {
		return nil, err
	}
	return fetchFiles(ctx, src, manifest)
}

func fetchManifest(ctx context.Context, src content.Fetcher, desc ocispec.Descriptor, artifactType string) (*ocispec.Manifest, error) {
	if desc.MediaType != ocispec.MediaTypeImageManifest {
		return nil, fmt.Errorf("%s has media type %q, want an OCI image manifest", desc.Digest, desc.MediaType)
	}
	data, err := fetchBlob(ctx, src, desc, MaxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decoding manifest %s: %w", desc.Digest, err)
	}
	if manifest.MediaType != ocispec.MediaTypeImageManifest {
		return nil, fmt.Errorf("manifest %s has media type %q, want an OCI image manifest", desc.Digest, manifest.MediaType)
	}
	if manifest.ArtifactType != artifactType {
		return nil, fmt.Errorf("%s is not a %s artifact (artifact type %q)", desc.Digest, project.Name, manifest.ArtifactType)
	}
	return &manifest, nil
}

func fetchFiles(ctx context.Context, src content.Fetcher, manifest *ocispec.Manifest) (map[string][]byte, error) {
	if len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != FilesMediaType {
		return nil, fmt.Errorf("want exactly one layer of media type %q", FilesMediaType)
	}
	layer, err := fetchBlob(ctx, src, manifest.Layers[0], MaxLayerSize)
	if err != nil {
		return nil, fmt.Errorf("files: %w", err)
	}
	return extract(layer)
}

// fetchBlob checks the size announced by desc before downloading, then the
// size and digest of what was downloaded.
func fetchBlob(ctx context.Context, src content.Fetcher, desc ocispec.Descriptor, limit int64) ([]byte, error) {
	if desc.Size < 0 || desc.Size > limit {
		return nil, fmt.Errorf("%s is %d bytes, more than the %d allowed", desc.Digest, desc.Size, limit)
	}
	if err := desc.Digest.Validate(); err != nil {
		return nil, err
	}
	if desc.Digest.Algorithm() != digest.SHA256 {
		return nil, fmt.Errorf("%s: only sha256 digests are accepted", desc.Digest)
	}
	return content.FetchAll(ctx, src, desc)
}
