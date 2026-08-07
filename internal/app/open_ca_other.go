//go:build !unix

package app

import "os"

func openInputFile(path string) (*os.File, error) {
	return os.Open(path)
}
