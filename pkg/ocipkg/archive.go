package ocipkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"time"

	"github.com/Sigeth/opslab-core-go/pkg/challenge"
)

// archive writes files as a reproducible tar+gzip archive: sorted entries,
// regular files only, fixed owner, mode and time. The manifest file is left
// out.
func archive(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		if name == challenge.ManifestFile {
			continue
		}
		if !fs.ValidPath(name) || name == "." {
			return nil, fmt.Errorf("%s: must be a relative path inside the package", name)
		}
		names = append(names, name)
	}
	slices.Sort(names)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		data := files[name]
		header := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(data)),
			Mode:     0o644,
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// extract reads an archive written by archive. It accepts only regular files
// with valid, unique paths, other than the manifest file, totalling at most
// challenge.MaxBundleSize bytes.
func extract(layer []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		return nil, fmt.Errorf("files: not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	remaining := int64(challenge.MaxBundleSize)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("files: %w", err)
		}
		name := header.Name
		switch {
		case header.Typeflag != tar.TypeReg:
			return nil, fmt.Errorf("files: %s: only regular files are allowed", name)
		case !fs.ValidPath(name) || name == ".":
			return nil, fmt.Errorf("files: %s: must be a relative path inside the package", name)
		case name == challenge.ManifestFile:
			return nil, fmt.Errorf("files: %s must not be in the files layer", name)
		case has(files, name):
			return nil, fmt.Errorf("files: %s appears twice", name)
		case header.Size > remaining:
			return nil, fmt.Errorf("files: more than the %d bytes allowed", challenge.MaxBundleSize)
		}
		data, err := io.ReadAll(io.LimitReader(tr, header.Size))
		if err != nil {
			return nil, fmt.Errorf("files: %s: %w", name, err)
		}
		remaining -= int64(len(data))
		files[name] = data
	}
}

func has(files map[string][]byte, name string) bool {
	_, ok := files[name]
	return ok
}
