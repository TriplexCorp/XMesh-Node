//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/recovery"
	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
)

func run(args []string) error {
	flags := flag.NewFlagSet("xmesh-xspv2-retirement-request", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateRoot := flags.String("state-root", state.DefaultRoot, "existing XSP-v2 Agent state root")
	checkpointPath := flags.String("checkpoint", "", "signed owner off-host recovery checkpoint JSON")
	requestID := flags.String("request-id", "", "unique operator retirement request ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *checkpointPath == "" || *requestID == "" {
		return errors.New("--checkpoint and --request-id are required and positional arguments are forbidden")
	}

	layout, err := state.Open(*stateRoot)
	if err != nil {
		return fmt.Errorf("open existing Agent state: %w", err)
	}
	rawCheckpoint, err := os.ReadFile(*checkpointPath)
	if err != nil {
		return fmt.Errorf("read recovery checkpoint: %w", err)
	}
	checkpoint, err := recovery.Decode(rawCheckpoint)
	if err != nil {
		return fmt.Errorf("decode recovery checkpoint: %w", err)
	}
	request, err := recovery.BuildRetirementRequest(checkpoint, layout, *requestID)
	if err != nil {
		return fmt.Errorf("build retirement request: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(request); err != nil {
		return fmt.Errorf("encode retirement request: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xmesh-xspv2-retirement-request:", err)
		os.Exit(1)
	}
}
