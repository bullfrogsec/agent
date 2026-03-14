package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	tetragonVersion = "v1.6.0"
	tetragonBPFDir  = "/var/lib/tetragon"
)

// ensureTetragon checks if a tetragon binary exists at destPath.
// If not, it downloads the release tarball from GitHub, extracts the
// binary to destPath and the BPF object files to tetragonBPFDir.
func ensureTetragon(destPath string) error {
	if _, err := os.Stat(destPath); err == nil {
		return nil // already exists
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("tetragon is only supported on linux, got %s", runtime.GOOS)
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported architecture: %s", arch)
	}

	url := fmt.Sprintf(
		"https://github.com/cilium/tetragon/releases/download/%s/tetragon-%s-%s.tar.gz",
		tetragonVersion, tetragonVersion, arch,
	)
	log.Printf("Downloading tetragon %s from %s", tetragonVersion, url)

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("creating directory for tetragon binary: %w", err)
	}
	if err := os.MkdirAll(tetragonBPFDir, 0755); err != nil {
		return fmt.Errorf("creating tetragon BPF dir: %w", err)
	}

	resp, err := http.Get(url) //nolint:gosec // URL is constructed from a hardcoded version constant
	if err != nil {
		return fmt.Errorf("downloading tetragon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading tetragon: HTTP %d from %s", resp.StatusCode, url)
	}

	binaryFound, bpfCount, err := extractTetragonArchive(resp.Body, destPath, tetragonBPFDir)
	if err != nil {
		return fmt.Errorf("extracting tetragon archive: %w", err)
	}
	if !binaryFound {
		return fmt.Errorf("tetragon binary not found in archive")
	}

	log.Printf("Tetragon installed: binary at %s, %d BPF object(s) at %s",
		destPath, bpfCount, tetragonBPFDir)
	return nil
}

// extractTetragonArchive reads a .tar.gz stream and:
//   - writes the "tetragon" binary to binaryPath (mode 0755, atomic rename)
//   - writes any *.o / *.o.gz files to bpfLibDir (mode 0644, atomic rename)
//
// Returns (binaryFound, bpfFileCount, error).
func extractTetragonArchive(r io.Reader, binaryPath, bpfLibDir string) (bool, int, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return false, 0, fmt.Errorf("opening gzip stream: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	binaryFound := false
	bpfCount := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, 0, fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		base := filepath.Base(hdr.Name)

		switch {
		case base == "tetragon":
			if err := writeFileAtomic(binaryPath, tr, 0755); err != nil {
				return false, 0, fmt.Errorf("writing tetragon binary: %w", err)
			}
			binaryFound = true

		case strings.HasSuffix(base, ".o") || strings.HasSuffix(base, ".o.gz"):
			dest := filepath.Join(bpfLibDir, base)
			if err := writeFileAtomic(dest, tr, 0644); err != nil {
				return false, 0, fmt.Errorf("writing BPF file %s: %w", base, err)
			}
			bpfCount++
		}
	}

	return binaryFound, bpfCount, nil
}

// writeFileAtomic writes r to destPath with the given mode using a temp file
// + rename so that a partial write never leaves a corrupt file.
func writeFileAtomic(destPath string, r io.Reader, mode os.FileMode) error {
	tmp := destPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, r)
	f.Close()
	if copyErr != nil {
		os.Remove(tmp)
		return copyErr
	}
	return os.Rename(tmp, destPath)
}
