package ocipkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
)

func testPackage(t *testing.T) (*v1alpha1.ChallengePackage, map[string][]byte) {
	t.Helper()
	files := os.DirFS("../challenge/testdata/ssh-hardening")
	pkg, err := challenge.Load(files)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := challenge.Bundle(pkg, files)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, bundle
}

func TestPackFetchRoundTrip(t *testing.T) {
	ctx := context.Background()
	pkg, bundle := testPackage(t)
	store := memory.New()
	desc, err := Pack(ctx, store, pkg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if desc.ArtifactType != ArtifactType || desc.Annotations[ocispec.AnnotationVersion] != pkg.Metadata.Version {
		t.Fatalf("descriptor = %+v", desc)
	}
	got, err := Fetch(ctx, store, desc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Manifest, pkg) {
		t.Errorf("manifest = %+v, want %+v", got.Manifest, pkg)
	}
	want := maps.Clone(bundle)
	delete(want, challenge.ManifestFile)
	if !reflect.DeepEqual(got.Files, want) {
		t.Errorf("files = %v, want %v", got.Files, want)
	}
}

func TestPackIsReproducible(t *testing.T) {
	ctx := context.Background()
	pkg, bundle := testPackage(t)
	first, err := Pack(ctx, memory.New(), pkg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Pack(ctx, memory.New(), pkg, maps.Clone(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("digests differ: %s and %s", first.Digest, second.Digest)
	}
}

func TestSolutionIsAReferrer(t *testing.T) {
	ctx := context.Background()
	pkg, bundle := testPackage(t)
	store := memory.New()
	subject, err := Pack(ctx, store, pkg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	solution := map[string][]byte{"solution/solve.sh": []byte("#!/bin/sh\n")}
	desc, err := PackSolution(ctx, store, subject, solution)
	if err != nil {
		t.Fatal(err)
	}
	referrers, err := registry.Referrers(ctx, store, subject, SolutionArtifactType)
	if err != nil {
		t.Fatal(err)
	}
	if len(referrers) != 1 || referrers[0].Digest != desc.Digest {
		t.Fatalf("referrers = %+v, want %s", referrers, desc.Digest)
	}
	got, err := FetchSolution(ctx, store, desc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, solution) {
		t.Fatalf("solution = %v", got)
	}
	if _, err := Fetch(ctx, store, desc); err == nil {
		t.Fatal("a solution must not be read as a package")
	}
}

// pushManifest stores a hand-made artifact with one files layer.
func pushManifest(t *testing.T, store *memory.Store, artifactType string, config, layer []byte) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	configDesc := content.NewDescriptorFromBytes(ConfigMediaType, config)
	layerDesc := content.NewDescriptorFromBytes(FilesMediaType, layer)
	manifest, _ := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       configDesc,
		Layers:       []ocispec.Descriptor{layerDesc},
	})
	desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifest)
	for _, b := range []struct {
		d ocispec.Descriptor
		b []byte
	}{{configDesc, config}, {layerDesc, layer}, {desc, manifest}} {
		if err := store.Push(ctx, b.d, bytes.NewReader(b.b)); err != nil {
			t.Fatal(err)
		}
	}
	return desc
}

func tarball(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		if h.Typeflag == tar.TypeReg && h.Size == 0 {
			h.Size = 1
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(make([]byte, h.Size))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestFetchRejectsBadArtifacts(t *testing.T) {
	pkg, _ := testPackage(t)
	config, _ := json.Marshal(pkg)
	reg := func(name string) *tar.Header { return &tar.Header{Typeflag: tar.TypeReg, Name: name} }
	cases := map[string]struct {
		artifactType string
		config       []byte
		layer        []byte
		want         string
	}{
		"wrong artifact type": {"application/vnd.example", config, tarball(t), "artifact type"},
		"unknown field":       {ArtifactType, []byte(`{"apiVersion":"opslab.io/v1alpha1","kind":"ChallengePackage","bogus":1}`), tarball(t), "bogus"},
		"path traversal":      {ArtifactType, config, tarball(t, reg("../etc/passwd")), "inside the package"},
		"absolute path":       {ArtifactType, config, tarball(t, reg("/etc/passwd")), "inside the package"},
		"symlink":             {ArtifactType, config, tarball(t, &tar.Header{Typeflag: tar.TypeSymlink, Name: "setup/x", Linkname: "/etc/shadow"}), "regular files"},
		"duplicate":           {ArtifactType, config, tarball(t, reg("setup/a.sh"), reg("setup/a.sh")), "twice"},
		"manifest in layer":   {ArtifactType, config, tarball(t, reg(challenge.ManifestFile)), "must not"},
		"too large":           {ArtifactType, config, tarball(t, &tar.Header{Typeflag: tar.TypeReg, Name: "big", Size: challenge.MaxBundleSize + 1}), "allowed"},
		"not gzip":            {ArtifactType, config, []byte("plain"), "gzip"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := memory.New()
			desc := pushManifest(t, store, tc.artifactType, tc.config, tc.layer)
			_, err := Fetch(context.Background(), store, desc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestFetchChecksAnnouncedSizes(t *testing.T) {
	pkg, bundle := testPackage(t)
	store := memory.New()
	desc, err := Pack(context.Background(), store, pkg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	desc.Size = MaxManifestSize + 1
	if _, err := Fetch(context.Background(), store, desc); err == nil || !strings.Contains(err.Error(), "allowed") {
		t.Fatalf("error = %v", err)
	}
}

func TestPinImages(t *testing.T) {
	d := digest.FromString("image")
	pinned := "ghcr.io/x/pinned:1@" + digest.FromString("other").String()
	pkg := &v1alpha1.ChallengePackage{Spec: v1alpha1.ChallengePackageSpec{
		Machines: []v1alpha1.Machine{
			{Name: "a", Image: "ghcr.io/x/a:1.0"},
			{Name: "b", Image: pinned},
			{Name: "k"}, // vcluster: no image
		},
		Validation: &v1alpha1.Validation{CheckerImage: "localhost:5000/checker:dev"},
	}}
	var resolved []string
	err := PinImages(context.Background(), pkg, func(_ context.Context, ref string) (digest.Digest, error) {
		resolved = append(resolved, ref)
		return d, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ghcr.io/x/a:1.0@" + d.String(), pinned, "localhost:5000/checker:dev@" + d.String()}
	if got := Images(pkg); !reflect.DeepEqual(got, want) {
		t.Fatalf("images = %v, want %v", got, want)
	}
	if len(resolved) != 2 {
		t.Fatalf("resolved %v, want only the unpinned images", resolved)
	}
	if u := Unpinned(pkg); len(u) != 0 {
		t.Fatalf("unpinned = %v", u)
	}
}

func TestPinImagesRefusesAmbiguousRefs(t *testing.T) {
	for _, ref := range []string{"ubuntu:24.04", "library/ubuntu:24.04", "ghcr.io/x/no-tag"} {
		pkg := &v1alpha1.ChallengePackage{Spec: v1alpha1.ChallengePackageSpec{
			Machines: []v1alpha1.Machine{{Name: "a", Image: ref}},
		}}
		err := PinImages(context.Background(), pkg, func(context.Context, string) (digest.Digest, error) {
			t.Fatalf("%s must not be resolved", ref)
			return "", nil
		})
		if err == nil {
			t.Errorf("%s: expected an error", ref)
		}
	}
}
