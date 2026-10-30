//go:build linux && xspv2_powercut_qualification && !xspv2_crash_test

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const (
	manifestSchema = "xsp2-kvm-manual-qualification-manifest-1"
	postbootSchema = "xsp2-kvm-manual-qualification-postboot-1"
	defaultRoot    = "/var/lib/xmesh/xspv2-kvm-qualification"
)

type manifest struct {
	Schema       string                       `json:"schema"`
	RunID        string                       `json:"runId"`
	Checkpoint   string                       `json:"checkpoint"`
	BootBeforeID string                       `json:"bootBeforeId"`
	Plan         keyring.KVMQualificationPlan `json:"plan"`
}

type rotationEvidence struct {
	FromEpoch   uint64 `json:"fromEpoch"`
	ToEpoch     uint64 `json:"toEpoch"`
	FromEdKeyID string `json:"fromEdKeyId"`
	FromPQKeyID string `json:"fromPQKeyId"`
	ToEdKeyID   string `json:"toEdKeyId"`
	ToPQKeyID   string `json:"toPQKeyId"`
}

type postbootEvidence struct {
	Schema                           string           `json:"schema"`
	RunID                            string           `json:"runId"`
	Checkpoint                       string           `json:"checkpoint"`
	BootBeforeID                     string           `json:"bootBeforeId"`
	BootAfterID                      string           `json:"bootAfterId"`
	NodeID                           int64            `json:"nodeId"`
	Rotation                         rotationEvidence `json:"rotation"`
	Classification                   string           `json:"classification"`
	KeyEpoch                         uint64           `json:"keyEpoch"`
	ActiveEdKeyID                    string           `json:"activeEdKeyId"`
	ActivePQKeyID                    string           `json:"activePQKeyId"`
	SecurityStateSHA256              string           `json:"securityStateSha256"`
	NetworkAttemptedBeforeValidation bool             `json:"networkAttemptedBeforeValidation"`
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "xspv2-kvm-qualify: "+format+"\n", args...)
	os.Exit(2)
}

func readBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" || strings.ContainsAny(id, " \t\r\n/") {
		return "", errors.New("invalid Linux boot_id")
	}
	return id, nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeJSONDurable(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncDir(filepath.Dir(path))
}

func loadManifest(path string) (manifest, error) {
	var out manifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&out); err != nil {
		return out, err
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return out, errors.New("trailing manifest data")
	}
	if out.Schema != manifestSchema || out.RunID == "" || out.Checkpoint == "" || out.BootBeforeID == "" {
		return out, errors.New("invalid qualification manifest")
	}
	return out, nil
}

func stateDigest(root string) (string, error) {
	base := filepath.Join(root, "private.json")
	paths := []string{base, base + ".min-epoch", base + ".next", base + ".previous"}
	sort.Strings(paths)
	h := sha256.New()
	seen := 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		seen++
		name := filepath.Base(path)
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(raw)
		_, _ = h.Write([]byte{0})
	}
	if seen == 0 {
		return "", errors.New("no persisted qualification state found")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runDir(root, runID string) string {
	return filepath.Join(root, runID)
}

func arm(args []string) {
	fs := flag.NewFlagSet("arm", flag.ExitOnError)
	root := fs.String("root", defaultRoot, "qualification root directory")
	runID := fs.String("run-id", "", "unique run ID (8..64 safe characters)")
	checkpoint := fs.String("checkpoint", "", "durability checkpoint")
	nodeID := fs.Int64("node-id", 0, "Node ID to bind into the isolated qualification keyring")
	_ = fs.Parse(args)
	if *runID == "" || *checkpoint == "" || *nodeID <= 0 {
		die("arm requires --run-id, --checkpoint and positive --node-id")
	}
	if err := os.MkdirAll(*root, 0o700); err != nil {
		die("create qualification root: %v", err)
	}
	if err := os.Chmod(*root, 0o700); err != nil {
		die("protect qualification root: %v", err)
	}
	bootID, err := readBootID()
	if err != nil {
		die("read boot ID: %v", err)
	}
	stateDir := runDir(*root, *runID)
	plan, err := keyring.PrepareKVMQualification(stateDir, *nodeID, *checkpoint)
	if err != nil {
		die("prepare run: %v", err)
	}
	m := manifest{Schema: manifestSchema, RunID: *runID, Checkpoint: *checkpoint, BootBeforeID: bootID, Plan: plan}
	if err = writeJSONDurable(filepath.Join(stateDir, "manifest.json"), m); err != nil {
		die("persist manifest before arming: %v", err)
	}

	// The keyring hook requires an inherited-looking fd >=3. Opening stdout via
	// /proc gives us a distinct descriptor while keeping the marker visible in
	// the operator's terminal.
	signal, err := os.OpenFile("/proc/self/fd/1", os.O_WRONLY, 0)
	if err != nil {
		die("open qualification signal descriptor: %v", err)
	}
	defer signal.Close()

	fmt.Printf("PREPARED run=%s point=%s boot=%s state=%s\n", *runID, *checkpoint, bootID, stateDir)
	fmt.Println("WAIT for XSP2-POWERCUT-ARMED-V1. Do NOT stop the VPS before that marker.")
	if err = keyring.ExecuteKVMQualification(plan, *runID, int(signal.Fd())); err != nil {
		die("qualification operation returned before external stop: %v", err)
	}
	die("qualification operation returned unexpectedly")
}

func inspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	root := fs.String("root", defaultRoot, "qualification root directory")
	runID := fs.String("run-id", "", "run ID used by arm")
	_ = fs.Parse(args)
	if *runID == "" {
		die("inspect requires --run-id")
	}
	stateDir := runDir(*root, *runID)
	m, err := loadManifest(filepath.Join(stateDir, "manifest.json"))
	if err != nil {
		die("load manifest: %v", err)
	}
	if m.RunID != *runID || m.Plan.StateDir != stateDir || m.Plan.Checkpoint != m.Checkpoint {
		die("manifest binding mismatch")
	}
	bootAfter, err := readBootID()
	if err != nil {
		die("read post-boot ID: %v", err)
	}
	if bootAfter == m.BootBeforeID {
		die("boot ID did not change; this is not a completed VPS stop/start run")
	}
	classification, active, err := keyring.InspectKVMQualification(m.Plan)
	if err != nil {
		die("post-boot keyring validation failed: %v", err)
	}
	digest, err := stateDigest(stateDir)
	if err != nil {
		die("hash recovered security state: %v", err)
	}
	evidence := postbootEvidence{
		Schema:       postbootSchema,
		RunID:        m.RunID,
		Checkpoint:   m.Checkpoint,
		BootBeforeID: m.BootBeforeID,
		BootAfterID:  bootAfter,
		NodeID:       active.NodeID,
		Rotation: rotationEvidence{
			FromEpoch:   m.Plan.Original.KeyEpoch,
			ToEpoch:     m.Plan.Candidate.KeyEpoch,
			FromEdKeyID: m.Plan.Original.EdKeyID,
			FromPQKeyID: m.Plan.Original.PQKeyID,
			ToEdKeyID:   m.Plan.Candidate.EdKeyID,
			ToPQKeyID:   m.Plan.Candidate.PQKeyID,
		},
		Classification:                   classification,
		KeyEpoch:                         active.KeyEpoch,
		ActiveEdKeyID:                    active.EdKeyID,
		ActivePQKeyID:                    active.PQKeyID,
		SecurityStateSHA256:              digest,
		NetworkAttemptedBeforeValidation: false,
	}
	path := filepath.Join(stateDir, "postboot.json")
	if err = writeJSONDurable(path, evidence); err != nil {
		die("persist post-boot evidence: %v", err)
	}
	raw, _ := json.MarshalIndent(evidence, "", "  ")
	fmt.Println(string(raw))
	fmt.Printf("PASS: keyring crash recovery validated; evidence=%s\n", path)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: xspv2-kvm-qualify <arm|inspect> [flags]")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "arm":
		arm(os.Args[2:])
	case "inspect":
		inspect(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}
