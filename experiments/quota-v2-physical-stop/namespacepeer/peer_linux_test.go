//go:build linux && amd64

package namespacepeer

import (
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCanonicalKernelIdentity(t *testing.T) {
	for _, value := range []string{"", "0", "+1", "01", "-1", "18446744073709551616"} {
		if _, err := uint64Field(value); err == nil {
			t.Fatalf("accepted noncanonical kernel identity %q", value)
		}
	}
	if n, err := uint64Field("18446744073709551615"); err != nil || n != ^uint64(0) {
		t.Fatalf("failed exact uint64 max: %d %v", n, err)
	}
}

func TestActualNamespaceMeterChild(t *testing.T) {
	// This binary is run with an actual inherited directory and sealed
	// manifest by the independent hosted root/PID namespace fixture.
	// Normal go test never manufactures a live peer or namespace.
	if os.Getenv("XMESH_DISPOSABLE_GO_NAMESPACE_PEER") != "1" {
		t.Skip("requires actual disposable namespace fixture")
	}
	if os.Getpid() != 1 || os.Getuid() != 0 || os.Getgid() != 0 {
		t.Fatal("not actual capless namespace init")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			if strings.Trim(strings.TrimSpace(value), "0") != "" {
				t.Fatalf("nonzero capability: %s", key)
			}
		case "NoNewPrivs":
			if strings.TrimSpace(value) != "1" {
				t.Fatal("no-new-privs missing")
			}
		}
	}
	manifestFD, err := strconv.Atoi(os.Getenv("XMESH_FIXTURE_MANIFEST_FD"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := os.Getenv("XMESH_FIXTURE_RUNTIME")
	roster := os.Getenv("XMESH_FIXTURE_ROSTER")
	verdict := os.Getenv("XMESH_FIXTURE_VERDICT")
	route, err := Open(manifestFD, runtime, roster)
	if verdict == "manifest-reject" {
		if err == nil {
			t.Fatal("changed manifest or original socket accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(manifestFD, strings.Repeat("0", 64), roster); err == nil {
		t.Fatal("foreign expected runtime accepted")
	}
	if _, err := Open(manifestFD, runtime, strings.Repeat("0", 64)); err == nil {
		t.Fatal("foreign expected roster accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, item := range [][2]string{
		{"xmesh-u999--vless-main", "vless-main"},
		{"xmesh-u100--vless-main", "vless-cdn"},
		{"xmesh-u100--vless-main", "foreign"},
	} {
		if c, err := route.Dial(ctx, item[0], item[1]); err == nil {
			c.Close()
			t.Fatalf("foreign alias/tag accepted: %v", item)
		}
	}
	if verdict == "peer-reject" {
		c, err := route.Dial(ctx, "xmesh-u100--vless-main", "vless-main")
		if err == nil {
			c.Close()
			t.Fatal("foreign pidfs token accepted")
		}
		if !strings.Contains(err.Error(), "not original live pidfs object") {
			t.Fatalf("unexpected peer proof failure: %v", err)
		}
		return
	}
	if verdict != "accept" {
		t.Fatalf("unknown fixture verdict %s", verdict)
	}
	for _, tag := range []string{"vless-main", "vless-cdn", "vless-main"} {
		c, err := route.Dial(ctx, "xmesh-u100--"+tag, tag)
		if err != nil {
			t.Fatal(err)
		}
		// No application traffic or permission, just the authenticated
		// actual kernel Unix endpoint.
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var fs syscall.Statfs_t
		if syscall.Fstatfs(fd, &fs) == nil && fs.Type == pidFSMagic {
			t.Fatal("original or newly opened peer pidfd leaked")
		}
	}
}
