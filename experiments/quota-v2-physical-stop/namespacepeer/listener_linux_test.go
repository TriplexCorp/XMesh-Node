//go:build linux && amd64

package namespacepeer

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestActualTransferredGoListener(t *testing.T) {
	if os.Getenv("XMESH_DISPOSABLE_GO_LISTENER") != "1" {
		t.Skip("requires isolated inherited listener fixture")
	}
	if os.Getpid() != 1 || os.Getuid() != 0 || os.Getgid() != 0 {
		t.Fatal("not actual root namespace init")
	}
	fd, err := strconv.Atoi(os.Getenv("XMESH_FIXTURE_LISTENER_FD"))
	if err != nil {
		t.Fatal(err)
	}
	var token BoundListenerToken
	if err := json.Unmarshal([]byte(os.Getenv("XMESH_FIXTURE_LISTENER_TOKEN")), &token); err != nil {
		t.Fatal(err)
	}
	if err := verifyListenerFD(fd, token, false); err != nil {
		t.Fatal(err)
	}
	// These tests use actual kernel state, not synthesized socket getters.
	for _, mutate := range []func(*BoundListenerToken){
		func(x *BoundListenerToken) { x.Address = "127.0.0.2" },
		func(x *BoundListenerToken) { x.Port++ },
		func(x *BoundListenerToken) { x.Device++ },
		func(x *BoundListenerToken) { x.Inode++ },
		func(x *BoundListenerToken) { x.Cookie ^= 1 },
		func(x *BoundListenerToken) { x.NetNSCookie ^= 1 },
	} {
		wrong := token
		mutate(&wrong)
		if err := verifyListenerFD(fd, wrong, false); err == nil {
			t.Fatal("foreign exact kernel token accepted")
		}
	}
	if err := verifyListenerFD(fd, token, true); err == nil {
		t.Fatal("unlistening socket accepted as listener")
	}
	// Kernel restriction must still hold AFTER exec into actual Go runtime.
	if c, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
		c.Close()
		t.Fatal("Go created independent TCP listener")
	} else if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("unexpected TCP listen refusal: %v", err)
	}
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:9", time.Second); err == nil {
		c.Close()
		t.Fatal("Go created independent TCP dial")
	} else if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("unexpected TCP dial refusal: %v", err)
	}
	fmt.Println("go_bound_verified")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || line != "fixture_go_adopt\n" {
		t.Fatal("missing exclusive-transfer fixture synchronization")
	}
	listener, err := AdoptTransferred(fd, token)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Close of original descriptor must precede the return; no duplicate
	// listener kept by the Go child after adoption.
	if _, err := fcntl(fd, syscall.F_GETFD); err == nil {
		t.Fatal("original descriptor retained after Go adoption")
	}
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var actual int
	if err := raw.Control(func(n uintptr) { actual = int(n) }); err != nil {
		t.Fatal(err)
	}
	if actual == fd || verifyListenerFD(actual, token, true) != nil {
		t.Fatal("pollable Go listener changed kernel identity")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	copies := 0
	for _, item := range entries {
		target, err := os.Readlink("/proc/self/fd/" + item.Name())
		if err == nil && target == fmt.Sprintf("socket:[%d]", token.Inode) {
			copies++
		}
	}
	if copies != 1 {
		t.Fatalf("expected exactly one child listener FD, got %d", copies)
	}
	fmt.Printf("go_listening_fd:%d\n", actual)
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := make([]byte, 7)
	if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "fixture" {
		t.Fatalf("inherited Go TCP read failed: %s %v", payload, err)
	}
	meter, err := net.DialTimeout("unix", os.Getenv("XMESH_FIXTURE_UNIX_PATH"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer meter.Close()
	meter.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := meter.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(meter, response); err != nil || string(response) != "echo" {
		t.Fatalf("Go Unix meter echo failed: %s %v", response, err)
	}
	if _, err := conn.Write(response); err != nil {
		t.Fatal(err)
	}
	fmt.Println("go_echo_complete")
	// The fixture must terminate this exact child via the independent
	// stop-only deadman, while the Go listener is still held.
	line, err = bufio.NewReader(os.Stdin).ReadString('\n')
	t.Fatalf("unexpected voluntary end before deadman: %q %v", line, err)
}
