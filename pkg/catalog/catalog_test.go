package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

func pkg(name, version, title string) *v1alpha1.ChallengePackage {
	return &v1alpha1.ChallengePackage{
		Metadata: v1alpha1.PackageMetadata{Name: name, Version: version},
		Spec: v1alpha1.ChallengePackageSpec{Title: title, Category: v1alpha1.CategoryLinuxHardening,
			Difficulty: v1alpha1.DifficultyEasy, Tags: []string{"ssh"}},
	}
}

func ref(name, version string) string {
	return "ghcr.io/sigeth/brokelabs-challenges/" + name + "@" + digest.FromString(name+version).String()
}

func TestAddKeepsVersionsSortedAndTheNewestMetadata(t *testing.T) {
	idx := New()
	for _, p := range []*v1alpha1.ChallengePackage{
		pkg("ssh-hardening", "1.0.0", "SSH v1"),
		pkg("ssh-hardening", "1.10.0", "SSH v1.10"),
		pkg("ssh-hardening", "1.2.0", "SSH v1.2"),
		pkg("auditd-watch", "0.1.0", "Auditd"),
	} {
		if err := Add(idx, p, nil, ref(p.Metadata.Name, p.Metadata.Version)); err != nil {
			t.Fatal(err)
		}
	}
	if errs := Validate(idx); len(errs) > 0 {
		t.Fatal(errs)
	}
	if idx.Packages[0].Name != "auditd-watch" || idx.Packages[1].Name != "ssh-hardening" {
		t.Fatalf("packages not sorted by name: %+v", idx.Packages)
	}
	ssh := idx.Packages[1]
	var got []string
	for _, v := range ssh.Versions {
		got = append(got, v.Version)
	}
	if strings.Join(got, ",") != "1.10.0,1.2.0,1.0.0" || ssh.Title != "SSH v1.10" {
		t.Fatalf("versions = %v, title = %q", got, ssh.Title)
	}
	if v, ok := Find(idx.Packages, "ssh-hardening", "1.2.0"); !ok || v.Ref != ref("ssh-hardening", "1.2.0") || v.Permissions == nil {
		t.Fatalf("Find = %+v, %v", v, ok)
	}
	if _, ok := Find(idx.Packages, "ssh-hardening", "9.9.9"); ok {
		t.Fatal("found a version that is not listed")
	}

	// Same version: idempotent with the same ref, refused with another.
	if err := Add(idx, pkg("ssh-hardening", "1.2.0", "x"), nil, ref("ssh-hardening", "1.2.0")); err != nil {
		t.Fatal(err)
	}
	if err := Add(idx, pkg("ssh-hardening", "1.2.0", "x"), nil, ref("other", "1")); err == nil {
		t.Fatal("a version cannot move to another digest")
	}
	if err := Add(idx, pkg("x", "1.0.0", "x"), nil, "ghcr.io/x/y:1.0.0"); err == nil {
		t.Fatal("refs must be pinned")
	}
}

func TestValidate(t *testing.T) {
	valid := func() *v1alpha1.CatalogIndex {
		idx := New()
		_ = Add(idx, pkg("ssh-hardening", "1.0.0", "SSH"), nil, ref("ssh-hardening", "1.0.0"))
		_ = Add(idx, pkg("ssh-hardening", "1.1.0", "SSH"), nil, ref("ssh-hardening", "1.1.0"))
		return idx
	}
	cases := map[string]struct {
		mutate func(*v1alpha1.CatalogIndex)
		want   string
	}{
		"kind":        {func(i *v1alpha1.CatalogIndex) { i.Kind = "Other" }, "kind"},
		"name":        {func(i *v1alpha1.CatalogIndex) { i.Packages[0].Name = "Bad_Name" }, "name"},
		"duplicate":   {func(i *v1alpha1.CatalogIndex) { i.Packages = append(i.Packages, i.Packages[0]) }, "Duplicate"},
		"category":    {func(i *v1alpha1.CatalogIndex) { i.Packages[0].Category = "cooking" }, "category"},
		"no versions": {func(i *v1alpha1.CatalogIndex) { i.Packages[0].Versions = nil }, "versions"},
		"unsorted": {func(i *v1alpha1.CatalogIndex) {
			v := i.Packages[0].Versions
			v[0], v[1] = v[1], v[0]
		}, "newest first"},
		"unpinned":       {func(i *v1alpha1.CatalogIndex) { i.Packages[0].Versions[0].Ref = "ghcr.io/x/y:1.1.0" }, "pinned"},
		"no permissions": {func(i *v1alpha1.CatalogIndex) { i.Packages[0].Versions[0].Permissions = nil }, "permissions"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			idx := valid()
			tc.mutate(idx)
			errs := Validate(idx)
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), tc.want) {
				t.Fatalf("errors = %v, want one about %q", errs, tc.want)
			}
		})
	}
}

func TestPackFetchRoundTrip(t *testing.T) {
	ctx := context.Background()
	idx := New()
	if err := Add(idx, pkg("ssh-hardening", "1.0.0", "SSH"), nil, ref("ssh-hardening", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	desc, err := Pack(ctx, store, idx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Fetch(ctx, store, desc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Index.Packages[0].Versions[0].Ref != ref("ssh-hardening", "1.0.0") || len(got.OCIManifest) == 0 {
		t.Fatalf("index = %+v", got.Index)
	}
	if again, _ := Pack(ctx, memory.New(), idx); again.Digest != desc.Digest {
		t.Fatal("packing must be reproducible")
	}

	if _, err := Pack(ctx, store, &v1alpha1.CatalogIndex{}); err == nil {
		t.Fatal("invalid indexes must not be packed")
	}
}

func TestFetchRefusesUnknownFieldsAndOtherArtifacts(t *testing.T) {
	ctx := context.Background()
	push := func(store *memory.Store, artifactType string, config []byte) ocispec.Descriptor {
		configDesc := content.NewDescriptorFromBytes(ConfigMediaType, config)
		manifest, _ := json.Marshal(ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, ArtifactType: artifactType,
			Config: configDesc, Layers: []ocispec.Descriptor{ocispec.DescriptorEmptyJSON}})
		desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifest)
		_ = store.Push(ctx, configDesc, bytes.NewReader(config))
		_ = store.Push(ctx, desc, bytes.NewReader(manifest))
		return desc
	}
	store := memory.New()
	unknown := push(store, ArtifactType, []byte(`{"apiVersion":"brokelabs.io/v1alpha1","kind":"CatalogIndex","packages":[],"extra":1}`))
	if _, err := Fetch(ctx, store, unknown); err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("error = %v", err)
	}
	other := push(store, "application/vnd.example", []byte(`{}`))
	if _, err := Fetch(ctx, store, other); err == nil || !strings.Contains(err.Error(), "not a") {
		t.Fatalf("error = %v", err)
	}
}
