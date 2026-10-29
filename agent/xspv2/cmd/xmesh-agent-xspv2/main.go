//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
)

// Release builds override both values with -ldflags. Keeping deliberately
// non-release defaults makes an accidentally unpinned binary fail --identity
// instead of looking like an approved staged package.
var (
	version        = "p0d1-staging"
	sourceRevision = "development"
)

type buildIdentity struct {
	Version        string `json:"version"`
	SourceRevision string `json:"sourceRevision"`
}

func validReleaseVersion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, char := range []byte(value) {
		if index == 0 {
			if !isASCIIAlphaNumeric(char) {
				return false
			}
			continue
		}
		if !isASCIIAlphaNumeric(char) && char != '.' && char != '_' && char != '+' && char != '-' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func validSourceRevision(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, char := range []byte(value) {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func releaseIdentity() (buildIdentity, error) {
	if !validReleaseVersion(version) {
		return buildIdentity{}, fmt.Errorf("invalid embedded release version")
	}
	if !validSourceRevision(sourceRevision) {
		return buildIdentity{}, fmt.Errorf("invalid or unpinned embedded source revision")
	}
	return buildIdentity{Version: version, SourceRevision: sourceRevision}, nil
}

func main() {
	stateRoot := flag.String("check-state", "", "validate/create the private XSP-v2 Agent state root")
	showVersion := flag.Bool("version", false, "print staging artifact version")
	showIdentity := flag.Bool("identity", false, "print exact embedded release build identity")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "positional commands are not supported")
		os.Exit(2)
	}

	actions := 0
	if *showVersion {
		actions++
	}
	if *showIdentity {
		actions++
	}
	if *stateRoot != "" {
		actions++
	}
	if actions != 1 {
		fmt.Fprintln(os.Stderr, "exactly one staging action is required; this artifact is not production-activated")
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *showIdentity {
		identity, err := releaseIdentity()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(identity); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	layout, err := state.Prepare(*stateRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
		"version":   version,
		"stateRoot": layout.Root,
		"journal":   layout.Journal,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
