package main

import (
	"runtime/debug"
	"testing"
)

func TestVersionFromBuild(t *testing.T) {
	tests := []struct {
		name   string
		linked string
		info   *debug.BuildInfo
		want   string
	}{
		{"release linker flag wins", "1.2.3", &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}}, "1.2.3"},
		{"module version", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, "1.2.3"},
		{"development build", "dev", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{"missing build info", "dev", nil, "dev"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := versionFromBuild(test.linked, test.info); got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
		})
	}
}
