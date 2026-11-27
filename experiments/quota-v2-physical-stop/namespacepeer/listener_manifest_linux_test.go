//go:build linux && amd64

package namespacepeer

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestActualSealedListenerManifest(t *testing.T) {
	if os.Getenv("XMESH_DISPOSABLE_GO_LISTENER_MANIFEST") != "1" {
		t.Skip("requires original signed config and inherited prebound sockets")
	}
	fd := func(key string) int {
		value, err := strconv.Atoi(os.Getenv(key))
		if err != nil || value < 3 {
			t.Fatalf("invalid fixture fd %s", key)
		}
		return value
	}
	manifest := fd("XMESH_FIXTURE_LISTENER_MANIFEST_FD")
	config := fd("XMESH_FIXTURE_LISTENER_CONFIG_FD")
	replacement := fd("XMESH_FIXTURE_LISTENER_REPLACEMENT_FD")
	bad := fd("XMESH_FIXTURE_BAD_LISTENER_MANIFEST_FD")
	runtime := os.Getenv("XMESH_FIXTURE_RUNTIME")
	roster := os.Getenv("XMESH_FIXTURE_ROSTER")
	authority := os.Getenv("XMESH_FIXTURE_AUTHORITY")
	configSHA := os.Getenv("XMESH_FIXTURE_CONFIG_SHA")
	set, err := OpenListeners(manifest, config, runtime, roster, authority, configSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.listeners) != 2 || set.listeners["vless-cdn"].token.Port != 443 ||
		set.listeners["vless-main"].token.Port != 8443 {
		t.Fatal("original MAIN/CDN scope not preserved")
	}
	if _, err := OpenListeners(bad, config, runtime, roster, authority, configSHA); err == nil {
		t.Fatal("noncanonical manifest accepted")
	}
	for i := 0; i < 4; i++ {
		values := []string{runtime, roster, authority, configSHA}
		values[i] = strings.Repeat("0", 64)
		if _, err := OpenListeners(manifest, config, values[0], values[1], values[2], values[3]); err == nil {
			t.Fatal("foreign independent digest accepted")
		}
	}
	if _, err := OpenListeners(manifest, replacement, runtime, roster, authority, configSHA); err == nil {
		t.Fatal("foreign config descriptor accepted")
	}
	for _, item := range []struct { tag,address string; port int }{
		{"vless-main","0.0.0.0",443}, {"vless-cdn","127.0.0.1",443},
		{"foreign","0.0.0.0",443},
	} {
		if listener, err := set.Adopt(item.tag,item.address,item.port); err == nil {
			listener.Close()
			t.Fatal("foreign adoption scope accepted")
		}
	}
	// Same bytes and seals in another actual inode cannot replace the
	// manifest after the original object was measured.
	if err := syscall.Dup3(replacement, manifest, syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if listener, err := set.Adopt("vless-main","0.0.0.0",8443); err == nil {
		listener.Close()
		t.Fatal("replaced retained manifest granted adoption")
	}
	// Nothing in this test starts a listener, including negative paths.
	for _, item := range set.listeners {
		if err := verifyListenerFD(item.fd,item.token,false); err != nil {
			t.Fatal(err)
		}
	}
}
