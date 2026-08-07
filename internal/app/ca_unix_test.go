//go:build unix

package app

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadRootsRejectsUnixSpecialFiles(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "bundle.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"fifo": fifo, "device": "/dev/null"} {
		t.Run(name, func(t *testing.T) {
			_, err := loadRoots(path, true)
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestReadTargetsRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "targets.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTargets(fifo); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRootsReportsUnreadableFile(t *testing.T) {
	path := writeTestCertificate(t)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	_, err := loadRoots(path, true)
	if err == nil {
		t.Skip("current user can read mode-000 files")
	}
	if !strings.Contains(err.Error(), "cannot be opened for reading") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRootsUsesAlreadyOpenedFileAfterReplacement(t *testing.T) {
	original := writeTestCertificate(t)
	want, err := loadRoots(original, true)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(t.TempDir(), "replacement.pem")
	if err := os.WriteFile(replacement, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := loadRootsAfterOpen(original, true, func() {
		if err := os.Rename(replacement, original); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatalf("open descriptor should retain original bundle: %v", err)
	}
	if !pool.Equal(want) {
		t.Fatal("opened descriptor did not retain the original bundle")
	}
	if _, err := loadRoots(original, true); err == nil || !strings.Contains(err.Error(), "not a valid PEM") {
		t.Fatalf("replacement path was not installed: %v", err)
	}
}
