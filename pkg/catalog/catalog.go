// Package catalog builds, stores and validates catalog indexes: the signed
// documents a catalog publishes to list its packages (D5, D40).
//
// An index is an OCI artifact of type ArtifactType whose config blob is the
// CatalogIndex as JSON. It is signed like a package (pkg/signing), over its
// OCI manifest.
package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"oras.land/oras-go/v2/content"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/ocipkg"
	"github.com/Sigeth/opslab-core-go/pkg/project"
)

// Media and artifact types.
var (
	// ArtifactType identifies a catalog index.
	ArtifactType = "application/vnd." + project.Name + ".catalog.v1"
	// ConfigMediaType is the media type of the config blob: the index as JSON.
	ConfigMediaType = "application/vnd." + project.Name + ".catalog.index.v1+json"
)

// Limits of an index. The operator copies the packages into the status of
// the CatalogSource, which must fit in a Kubernetes object.
const (
	MaxIndexSize = 512 << 10
	MaxPackages  = 500
	MaxVersions  = 50
)

// maxManifestSize bounds the OCI manifest of an index.
const maxManifestSize = 16 << 10

// New returns an empty index.
func New() *v1alpha1.CatalogIndex {
	return &v1alpha1.CatalogIndex{APIVersion: v1alpha1.GroupVersion.String(), Kind: v1alpha1.CatalogIndexKind, Packages: []v1alpha1.CatalogEntry{}}
}

// Add lists version pkg.Metadata.Version of a package, published at ref
// (pinned by digest). The newest version gives the title, summary and tags
// of the entry; versions stay sorted newest first. Adding a version again
// with the same ref does nothing, with another ref is an error.
func Add(idx *v1alpha1.CatalogIndex, pkg *v1alpha1.ChallengePackage, ref string) error {
	version, err := semver.StrictNewVersion(pkg.Metadata.Version)
	if err != nil {
		return fmt.Errorf("%s: version %q: %w", pkg.Metadata.Name, pkg.Metadata.Version, err)
	}
	if !ocipkg.Pinned(ref) {
		return fmt.Errorf("%s: %s must be pinned by digest", pkg.Metadata.Name, ref)
	}
	i := slices.IndexFunc(idx.Packages, func(e v1alpha1.CatalogEntry) bool { return e.Name == pkg.Metadata.Name })
	if i < 0 {
		idx.Packages = append(idx.Packages, v1alpha1.CatalogEntry{Name: pkg.Metadata.Name})
		i = len(idx.Packages) - 1
	}
	entry := &idx.Packages[i]
	for _, v := range entry.Versions {
		if v.Version == pkg.Metadata.Version {
			if v.Ref == ref {
				return nil
			}
			return fmt.Errorf("%s %s is already listed at %s", pkg.Metadata.Name, v.Version, v.Ref)
		}
	}
	entry.Versions = append(entry.Versions, v1alpha1.CatalogVersion{Version: pkg.Metadata.Version, Ref: ref})
	sortVersions(entry.Versions)
	if entry.Versions[0].Version == version.Original() {
		s := pkg.Spec
		entry.Title, entry.Summary, entry.Category, entry.Difficulty, entry.Tags = s.Title, s.Summary, s.Category, s.Difficulty, s.Tags
	}
	slices.SortFunc(idx.Packages, func(a, b v1alpha1.CatalogEntry) int { return strings.Compare(a.Name, b.Name) })
	return nil
}

// sortVersions sorts valid semantic versions newest first.
func sortVersions(versions []v1alpha1.CatalogVersion) {
	slices.SortStableFunc(versions, func(a, b v1alpha1.CatalogVersion) int {
		va, errA := semver.StrictNewVersion(a.Version)
		vb, errB := semver.StrictNewVersion(b.Version)
		if errA != nil || errB != nil {
			return 0
		}
		return vb.Compare(va)
	})
}

// Find returns the ref of version of package name.
func Find(packages []v1alpha1.CatalogEntry, name, version string) (string, bool) {
	for _, e := range packages {
		if e.Name != name {
			continue
		}
		for _, v := range e.Versions {
			if v.Version == version {
				return v.Ref, true
			}
		}
	}
	return "", false
}

// Validate checks an index: header, unique DNS-label names, known categories
// and difficulties, unique semantic versions sorted newest first, refs pinned
// by digest, and the size limits.
func Validate(idx *v1alpha1.CatalogIndex) field.ErrorList {
	var errs field.ErrorList
	if want := v1alpha1.GroupVersion.String(); idx.APIVersion != want {
		errs = append(errs, field.NotSupported(field.NewPath("apiVersion"), idx.APIVersion, []string{want}))
	}
	if idx.Kind != v1alpha1.CatalogIndexKind {
		errs = append(errs, field.NotSupported(field.NewPath("kind"), idx.Kind, []string{v1alpha1.CatalogIndexKind}))
	}
	pkgs := field.NewPath("packages")
	if len(idx.Packages) > MaxPackages {
		errs = append(errs, field.TooMany(pkgs, len(idx.Packages), MaxPackages))
	}
	names := map[string]bool{}
	for i, e := range idx.Packages {
		fp := pkgs.Index(i)
		for _, msg := range validation.IsDNS1123Label(e.Name) {
			errs = append(errs, field.Invalid(fp.Child("name"), e.Name, msg))
		}
		if names[e.Name] {
			errs = append(errs, field.Duplicate(fp.Child("name"), e.Name))
		}
		names[e.Name] = true
		if e.Title == "" {
			errs = append(errs, field.Required(fp.Child("title"), ""))
		}
		if !slices.Contains(v1alpha1.Categories, e.Category) {
			errs = append(errs, field.NotSupported(fp.Child("category"), e.Category, v1alpha1.Categories))
		}
		if !slices.Contains(v1alpha1.Difficulties, e.Difficulty) {
			errs = append(errs, field.NotSupported(fp.Child("difficulty"), e.Difficulty, v1alpha1.Difficulties))
		}
		errs = append(errs, validateVersions(e.Versions, fp.Child("versions"))...)
	}
	return errs
}

func validateVersions(versions []v1alpha1.CatalogVersion, fp *field.Path) field.ErrorList {
	var errs field.ErrorList
	switch {
	case len(versions) == 0:
		errs = append(errs, field.Required(fp, "at least one version"))
	case len(versions) > MaxVersions:
		errs = append(errs, field.TooMany(fp, len(versions), MaxVersions))
	}
	var previous *semver.Version
	seen := map[string]bool{}
	for j, v := range versions {
		vp := fp.Index(j)
		version, err := semver.StrictNewVersion(v.Version)
		if err != nil {
			errs = append(errs, field.Invalid(vp.Child("version"), v.Version, "must be a semantic version such as 1.2.0"))
		} else {
			if previous != nil && !version.LessThan(previous) {
				errs = append(errs, field.Invalid(vp.Child("version"), v.Version, "versions must be unique and sorted newest first"))
			}
			previous = version
		}
		if seen[v.Version] {
			errs = append(errs, field.Duplicate(vp.Child("version"), v.Version))
		}
		seen[v.Version] = true
		if _, err := ocipkg.ParseImage(v.Ref); err != nil || !ocipkg.Pinned(v.Ref) {
			errs = append(errs, field.Invalid(vp.Child("ref"), v.Ref, "must be an OCI reference pinned by digest (registry/repository@sha256:...)"))
		}
	}
	return errs
}

// Index is a catalog index read from an OCI artifact.
type Index struct {
	// Descriptor of the OCI manifest.
	Descriptor ocispec.Descriptor
	// OCIManifest is the OCI manifest as stored, the content signatures sign.
	OCIManifest []byte
	// Index is the validated catalog index.
	Index *v1alpha1.CatalogIndex
}

// Pack validates idx and stores it in dst. It returns the descriptor of the
// OCI manifest.
func Pack(ctx context.Context, dst content.Pusher, idx *v1alpha1.CatalogIndex) (ocispec.Descriptor, error) {
	if errs := Validate(idx); len(errs) > 0 {
		return ocispec.Descriptor{}, fmt.Errorf("invalid catalog index: %v", errs.ToAggregate())
	}
	config, err := json.Marshal(idx)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if len(config) > MaxIndexSize {
		return ocispec.Descriptor{}, fmt.Errorf("the index is %d bytes, more than the %d allowed", len(config), MaxIndexSize)
	}
	configDesc := content.NewDescriptorFromBytes(ConfigMediaType, config)
	manifest, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactType,
		Config:       configDesc,
		Layers:       []ocispec.Descriptor{ocispec.DescriptorEmptyJSON},
	})
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifest)
	desc.ArtifactType = ArtifactType
	for _, blob := range []struct {
		desc ocispec.Descriptor
		data []byte
	}{{configDesc, config}, {ocispec.DescriptorEmptyJSON, ocispec.DescriptorEmptyJSON.Data}, {desc, manifest}} {
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

// Fetch reads and validates the index whose OCI manifest is desc.
func Fetch(ctx context.Context, src content.Fetcher, desc ocispec.Descriptor) (*Index, error) {
	if desc.MediaType != ocispec.MediaTypeImageManifest || desc.Size > maxManifestSize {
		return nil, fmt.Errorf("%s: not a catalog index (%s, %d bytes)", desc.Digest, desc.MediaType, desc.Size)
	}
	raw, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return nil, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decoding manifest %s: %w", desc.Digest, err)
	}
	if manifest.ArtifactType != ArtifactType || manifest.Config.MediaType != ConfigMediaType {
		return nil, fmt.Errorf("%s is not a catalog index (artifact type %q)", desc.Digest, manifest.ArtifactType)
	}
	if manifest.Config.Size > MaxIndexSize {
		return nil, fmt.Errorf("the index is %d bytes, more than the %d allowed", manifest.Config.Size, MaxIndexSize)
	}
	config, err := content.FetchAll(ctx, src, manifest.Config)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(config))
	dec.DisallowUnknownFields()
	idx := &v1alpha1.CatalogIndex{}
	if err := dec.Decode(idx); err != nil {
		return nil, fmt.Errorf("decoding the index: %w", err)
	}
	if errs := Validate(idx); len(errs) > 0 {
		return nil, fmt.Errorf("invalid catalog index: %v", errs.ToAggregate())
	}
	return &Index{Descriptor: desc, OCIManifest: raw, Index: idx}, nil
}
