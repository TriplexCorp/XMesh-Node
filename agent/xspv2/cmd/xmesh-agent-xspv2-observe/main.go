//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/observability"
)

const observabilityGate = "staging-only"

func main() {
	stateRoot := flag.String("state-root", "", "existing private XSP-v2 Agent state root")
	flag.Parse()
	if flag.NArg() != 0 || *stateRoot == "" {
		fmt.Fprintln(os.Stderr, "exactly --state-root is required")
		os.Exit(2)
	}
	if os.Getenv("XSP_V2_OBSERVABILITY") != observabilityGate {
		fmt.Fprintln(os.Stderr, "XSP_V2_OBSERVABILITY must equal staging-only")
		os.Exit(1)
	}

	snapshot, err := observability.Snapshot(*stateRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(snapshot); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
