//go:build unix

package app

import (
	"os"
	"syscall"
)

func openInputFile(path string) (*os.File, error) {
	// #nosec G304 -- the operator intentionally selects an arbitrary input path;
	// descriptor validation and a bounded read happen immediately after open.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
