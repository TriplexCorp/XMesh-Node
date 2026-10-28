//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
)

const version = "p0d1-staging"

func main() {
	stateRoot := flag.String("check-state", "", "validate/create the private XSP-v2 Agent state root")
	showVersion := flag.Bool("version", false, "print staging artifact version")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "positional commands are not supported")
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *stateRoot == "" {
		fmt.Fprintln(os.Stderr, "no action requested; this P0-D artifact is not production-activated")
		os.Exit(2)
	}
	layout, err := state.Prepare(*stateRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
		"version": version,
		"stateRoot": layout.Root,
		"journal": layout.Journal,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
