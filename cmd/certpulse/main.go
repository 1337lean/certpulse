package main

import (
	"os"
	"runtime/debug"
	"strings"

	"github.com/1337lean/certpulse/internal/app"
)

var version = "dev"

func main() { os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr, resolvedVersion())) }

func resolvedVersion() string {
	info, _ := debug.ReadBuildInfo()
	return versionFromBuild(version, info)
}

func versionFromBuild(linked string, info *debug.BuildInfo) string {
	if linked != "dev" {
		return linked
	}
	if info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return linked
}
