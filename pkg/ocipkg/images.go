package ocipkg

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/project"
)

// Resolver returns the digest an image reference points to.
type Resolver func(ctx context.Context, ref string) (digest.Digest, error)

// imageRefs returns every image reference of a package: machine images and
// the custom checker.
func imageRefs(pkg *v1alpha1.ChallengePackage) []*string {
	var refs []*string
	for i := range pkg.Spec.Machines {
		if pkg.Spec.Machines[i].Image != "" {
			refs = append(refs, &pkg.Spec.Machines[i].Image)
		}
	}
	if v := pkg.Spec.Validation; v != nil && v.CheckerImage != "" {
		refs = append(refs, &v.CheckerImage)
	}
	return refs
}

// Images returns the image references of a package, in order.
func Images(pkg *v1alpha1.ChallengePackage) []string {
	var images []string
	for _, ref := range imageRefs(pkg) {
		images = append(images, *ref)
	}
	return images
}

// ParseImage parses a fully qualified image reference
// (registry/repository[:tag][@digest]). Short Docker Hub names such as
// "ubuntu:24.04" are refused: the registry must be explicit.
func ParseImage(ref string) (registry.Reference, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		return registry.Reference{}, err
	}
	host := parsed.Registry
	if !strings.ContainsAny(host, ".:") && host != "localhost" {
		return registry.Reference{}, fmt.Errorf("%s: name the registry (e.g. docker.io/library/%s)", ref, strings.TrimPrefix(ref, host+"/"))
	}
	return parsed, nil
}

// Pinned reports whether ref names a digest.
func Pinned(ref string) bool {
	parsed, err := ParseImage(ref)
	if err != nil {
		return false
	}
	_, err = parsed.Digest()
	return err == nil
}

// Unpinned returns the image references of a package that are not pinned by
// digest.
func Unpinned(pkg *v1alpha1.ChallengePackage) []string {
	var refs []string
	for _, ref := range Images(pkg) {
		if !Pinned(ref) {
			refs = append(refs, ref)
		}
	}
	return refs
}

// PinImages pins every image reference of pkg by digest, keeping the tag for
// readers (registry/repository:tag@sha256:...). References already pinned are
// kept as they are.
func PinImages(ctx context.Context, pkg *v1alpha1.ChallengePackage, resolve Resolver) error {
	var errs []error
	for _, ref := range imageRefs(pkg) {
		parsed, err := ParseImage(*ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if parsed.Reference == "" {
			errs = append(errs, fmt.Errorf("%s: name a tag or a digest", *ref))
			continue
		}
		if Pinned(*ref) {
			continue
		}
		d, err := resolve(ctx, *ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("resolving %s: %w", *ref, err))
			continue
		}
		*ref = *ref + "@" + d.String()
	}
	return errors.Join(errs...)
}

// Remote reaches OCI registries.
type Remote struct {
	// Credential returns the credentials of a registry. Nil means anonymous.
	Credential auth.CredentialFunc
	// PlainHTTP reports whether a registry is reached over plain HTTP (local
	// test registries only). Nil means HTTPS everywhere.
	PlainHTTP func(registry string) bool
}

// Repository returns the repository of ref and the parsed reference.
func (r Remote) Repository(ref string) (*remote.Repository, registry.Reference, error) {
	parsed, err := ParseImage(ref)
	if err != nil {
		return nil, registry.Reference{}, err
	}
	repo, err := remote.NewRepository(parsed.Registry + "/" + parsed.Repository)
	if err != nil {
		return nil, registry.Reference{}, err
	}
	repo.Client = &auth.Client{
		Client:     retry.DefaultClient,
		Header:     http.Header{"User-Agent": {project.Name}},
		Cache:      auth.NewCache(),
		Credential: r.Credential,
	}
	repo.PlainHTTP = r.PlainHTTP != nil && r.PlainHTTP(parsed.Registry)
	// Registries without the referrers API (ghcr.io) keep referrers in a
	// tagged index that each new referrer replaces. Deleting the replaced
	// index is refused by some of them (ghcr.io answers 405): leave it.
	repo.SkipReferrersGC = true
	return repo, parsed, nil
}

// Resolve returns the descriptor ref points to. When ref names both a tag and
// a digest, the digest wins.
func (r Remote) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	repo, parsed, err := r.Repository(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return repo.Resolve(ctx, parsed.Reference)
}

// Resolver adapts Resolve for PinImages.
func (r Remote) Resolver() Resolver {
	return func(ctx context.Context, ref string) (digest.Digest, error) {
		desc, err := r.Resolve(ctx, ref)
		return desc.Digest, err
	}
}
