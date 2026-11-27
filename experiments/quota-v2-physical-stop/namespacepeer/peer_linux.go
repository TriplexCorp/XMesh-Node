//go:build linux && amd64

// Package namespacepeer is a dormant standard-library Go kernel peer
// verifier for the future isolated TLS child. It is NOT connected to the
// installed Xray artifact or any positive ingress authority.
package namespacepeer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	maxManifest = 1 << 20
	fGetSeals   = 1034
	allSeals    = 15
	pidFSMagic  = 0x50494446
	soPeerPidFD = 77
	soDomain    = 39
	vfsFlags    = 1 | 2 | 4 | 8 // readonly, nosuid, nodev, noexec
)

var hex64 = regexp.MustCompile("^[0-9a-f]{64}$")
var signedAlias = regexp.MustCompile("^xmesh-u[1-9][0-9]{0,18}--vless-(main|cdn)$")

// Field order is the canonical Python sorted-key wire format.
// Re-encoding must exactly reproduce the sealed bytes (including no
// duplicates, noncanonical numbers, unknown keys or trailing whitespace).
type socketRecord struct {
	Device string `json:"device"`
	Inode  string `json:"inode"`
	Tag    string `json:"tag"`
}

type manifest struct {
	Aliases              []string       `json:"aliases"`
	Kind                 string         `json:"kind"`
	MeterDirectoryDevice string         `json:"meterDirectoryDevice"`
	MeterDirectoryFD     int            `json:"meterDirectoryFd"`
	MeterDirectoryInode  string         `json:"meterDirectoryInode"`
	MeterMountID         string         `json:"meterMountId"`
	PeerDevice           string         `json:"peerDevice"`
	PeerInode            string         `json:"peerInode"`
	RosterSHA256         string         `json:"rosterSha256"`
	RuntimeID            string         `json:"runtimeId"`
	Sockets              []socketRecord `json:"sockets"`
	Version              int            `json:"version"`
}

type identity struct {
	dev uint64
	ino uint64
}

type Route struct {
	manifestFD int
	manifestID identity
	raw        []byte
	m          manifest
	directory  identity
	peer       identity
	mount      uint64
	aliases    map[string]bool
	sockets    map[string]identity
}

func uint64Field(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("invalid canonical kernel identity")
	}
	return n, nil
}

func inode(dev, ino string) (identity, error) {
	d, err := uint64Field(dev)
	if err != nil {
		return identity{}, err
	}
	i, err := uint64Field(ino)
	return identity{d, i}, err
}

func statID(s *syscall.Stat_t) identity {
	return identity{uint64(s.Dev), uint64(s.Ino)}
}

func fcntl(fd, command int) (uintptr, error) {
	x, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(command), 0)
	if err != 0 {
		return 0, err
	}
	return x, nil
}

func readSealed(fd int) ([]byte, identity, error) {
	return readSealedLimit(fd, maxManifest)
}

func readSealedLimit(fd, limit int) ([]byte, identity, error) {
	var before, after syscall.Stat_t
	if fd < 3 || syscall.Fstat(fd, &before) != nil ||
		before.Mode != syscall.S_IFREG|0600 || before.Uid != 0 ||
		before.Gid != 0 || before.Nlink != 0 || before.Size <= 0 || before.Size > int64(limit) {
		return nil, identity{}, errors.New("invalid sealed namespace manifest FD")
	}
	if seals, err := fcntl(fd, fGetSeals); err != nil || seals != allSeals {
		return nil, identity{}, errors.New("namespace manifest not exactly sealed")
	}
	raw := make([]byte, int(before.Size)+1)
	n, err := syscall.Pread(fd, raw, 0)
	if err != nil || n != int(before.Size) || syscall.Fstat(fd, &after) != nil ||
		statID(&before) != statID(&after) || after.Mode != before.Mode ||
		after.Size != before.Size || after.Nlink != before.Nlink ||
		after.Uid != before.Uid || after.Gid != before.Gid {
		return nil, identity{}, errors.New("namespace manifest changed during read")
	}
	return raw[:n], statID(&before), nil
}

func decimalField(file, key string, allowZero bool) (uint64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) == 0 || len(raw) > 8192 {
		return 0, errors.New("invalid bounded kernel fdinfo")
	}
	var n uint64
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		k, value, ok := strings.Cut(line, ":")
		if !ok || k != key {
			continue
		}
		s := strings.TrimSpace(value)
		n, err = strconv.ParseUint(s, 10, 64)
		if seen || err != nil || (!allowZero && n == 0) || strconv.FormatUint(n, 10) != s {
			return 0, errors.New("invalid or duplicate kernel fdinfo identity")
		}
		seen = true
	}
	if !seen {
		return 0, errors.New("missing kernel fdinfo identity")
	}
	return n, nil
}

func fdinfo(fd int) string { return fmt.Sprintf("/proc/self/fdinfo/%d", fd) }

func (r *Route) directoryPath() string {
	return fmt.Sprintf("/proc/self/fd/%d/.", r.m.MeterDirectoryFD)
}

// Open accepts only the original sealed manifest AND independently expected
// signed runtime/roster hashes. The owning supervisor remains responsible
// for original capsule liveness, stop-chain and authority. The returned
// object never opens a TCP listener, falls back to another route, or admits
// bytes on behalf of a caller.
func Open(manifestFD int, expectedRuntime, expectedRoster string) (*Route, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 ||
		!hex64.MatchString(expectedRuntime) || !hex64.MatchString(expectedRoster) {
		return nil, errors.New("root and independently pinned runtime/roster required")
	}
	raw, id, err := readSealed(manifestFD)
	if err != nil {
		return nil, err
	}
	r := &Route{manifestFD: manifestFD, manifestID: id, raw: raw,
		aliases: make(map[string]bool), sockets: make(map[string]identity)}
	if err := json.Unmarshal(raw, &r.m); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(r.m)
	if err != nil || !bytes.Equal(canonical, raw) ||
		r.m.Kind != "xmesh.quota-v2.namespace-meter-inputs" || r.m.Version != 1 ||
		r.m.RuntimeID != expectedRuntime || r.m.RosterSHA256 != expectedRoster ||
		r.m.MeterDirectoryFD < 3 || r.m.MeterDirectoryFD == manifestFD ||
		len(r.m.Aliases) == 0 || len(r.m.Aliases) > 4096 ||
		len(r.m.Sockets) == 0 || len(r.m.Sockets) > 2 {
		return nil, errors.New("foreign or noncanonical namespace meter manifest")
	}
	r.directory, err = inode(r.m.MeterDirectoryDevice, r.m.MeterDirectoryInode)
	if err != nil {
		return nil, err
	}
	r.peer, err = inode(r.m.PeerDevice, r.m.PeerInode)
	if err != nil {
		return nil, err
	}
	r.mount, err = uint64Field(r.m.MeterMountID)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]bool)
	for i, alias := range r.m.Aliases {
		if !signedAlias.MatchString(alias) || (i > 0 && r.m.Aliases[i-1] >= alias) {
			return nil, errors.New("foreign, duplicate or unsorted signed alias")
		}
		r.aliases[alias] = true
		tag := alias[strings.LastIndex(alias, "--")+2:]
		tags[tag] = true
	}
	for i, item := range r.m.Sockets {
		if !tags[item.Tag] || (i > 0 && r.m.Sockets[i-1].Tag >= item.Tag) {
			return nil, errors.New("foreign, duplicate or unsorted original socket")
		}
		id, err := inode(item.Device, item.Inode)
		if err != nil {
			return nil, err
		}
		r.sockets[item.Tag] = id
	}
	if len(r.sockets) != len(tags) {
		return nil, errors.New("incomplete original socket roster")
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	// Never leak these inherited descriptors into any subsequent exec.
	syscall.CloseOnExec(manifestFD)
	syscall.CloseOnExec(r.m.MeterDirectoryFD)
	return r, nil
}

func (r *Route) checkSocket(tag string) error {
	expected, ok := r.sockets[tag]
	var info syscall.Stat_t
	if !ok || syscall.Lstat(filepath.Join(r.directoryPath(), tag), &info) != nil ||
		info.Mode != syscall.S_IFSOCK|0600 || info.Uid != 0 || info.Gid != 0 ||
		info.Nlink != 1 || statID(&info) != expected {
		return errors.New("original meter listener inode changed")
	}
	return nil
}

func (r *Route) check() error {
	raw, id, err := readSealed(r.manifestFD)
	if err != nil || id != r.manifestID || !bytes.Equal(raw, r.raw) {
		return errors.New("original sealed namespace manifest changed")
	}
	var dir, parent syscall.Stat_t
	var fs syscall.Statfs_t
	fd := r.m.MeterDirectoryFD
	if syscall.Fstat(fd, &dir) != nil || dir.Mode != syscall.S_IFDIR|0700 ||
		dir.Uid != 0 || dir.Gid != 0 || statID(&dir) != r.directory ||
		syscall.Fstatfs(fd, &fs) != nil || fs.Flags&vfsFlags != vfsFlags ||
		syscall.Stat(r.directoryPath()+"/..", &parent) != nil || statID(&parent) != r.directory {
		return errors.New("original detached readonly meter directory changed")
	}
	mount, err := decimalField(fdinfo(fd), "mnt_id", false)
	if err != nil || mount != r.mount {
		return errors.New("original meter mount identity changed")
	}
	entries, err := os.ReadDir(r.directoryPath())
	if err != nil || len(entries) != len(r.sockets) {
		return errors.New("foreign or absent original meter socket")
	}
	for _, entry := range entries {
		if err := r.checkSocket(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func livePIDFD(fd int) error {
	ep, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return err
	}
	defer syscall.Close(ep)
	event := syscall.EpollEvent{Events: syscall.EPOLLIN | syscall.EPOLLHUP | syscall.EPOLLERR, Fd: int32(fd)}
	if err := syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, fd, &event); err != nil {
		return err
	}
	var events [1]syscall.EpollEvent
	n, err := syscall.EpollWait(ep, events[:], 0)
	if err != nil || n != 0 {
		return errors.New("original meter peer no longer live")
	}
	return nil
}

func checkPeer(fd int, expected identity) error {
	domain, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soDomain)
	if err != nil || domain != syscall.AF_UNIX {
		return errors.New("expected a connected Unix socket")
	}
	kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil || kind != syscall.SOCK_STREAM {
		return errors.New("expected a Unix stream")
	}
	if _, err := syscall.Getpeername(fd); err != nil {
		return err
	}
	// In a private PID namespace the original meter is invisible: PID=0
	// is necessary but never enough. Root UID/GID alone is not identity.
	cred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || cred == nil || *cred != (syscall.Ucred{Pid: 0, Uid: 0, Gid: 0}) {
		return errors.New("foreign or visible Unix meter peer")
	}
	pidfd, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soPeerPidFD)
	if err != nil || pidfd < 0 {
		return errors.New("kernel did not return a peer pidfd")
	}
	defer syscall.Close(pidfd)
	flags, err := fcntl(pidfd, syscall.F_GETFD)
	var fs syscall.Statfs_t
	var before, after syscall.Stat_t
	if err != nil || flags&syscall.FD_CLOEXEC == 0 ||
		syscall.Fstatfs(pidfd, &fs) != nil || fs.Type != pidFSMagic ||
		syscall.Fstat(pidfd, &before) != nil || statID(&before) != expected {
		return errors.New("Unix peer is not original live pidfs object")
	}
	if err := livePIDFD(pidfd); err != nil {
		return err
	}
	pid, err := decimalField(fdinfo(pidfd), "Pid", true)
	again, credErr := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || pid != 0 || credErr != nil || again == nil || *again != *cred ||
		syscall.Fstat(pidfd, &after) != nil || statID(&after) != expected {
		return errors.New("Unix peer changed during kernel proof")
	}
	return livePIDFD(pidfd)
}

// Dial returns a connected stream only after exact signed alias/tag and
// original kernel directory/listener/peer readback. No application bytes
// have been written by this function. No DNS, host PID path or fallback.
func (r *Route) Dial(ctx context.Context, alias, tag string) (net.Conn, error) {
	if r == nil || ctx == nil || !r.aliases[alias] ||
		(tag != "vless-main" && tag != "vless-cdn") || !strings.HasSuffix(alias, "--"+tag) {
		return nil, errors.New("private route outside exact signed alias scope")
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", filepath.Join(r.directoryPath(), tag))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return fail(errors.New("unexpected non-Unix connection"))
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return fail(err)
	}
	var peerErr error
	if err := raw.Control(func(fd uintptr) { peerErr = checkPeer(int(fd), r.peer) }); err != nil {
		return fail(err)
	}
	if peerErr != nil {
		return fail(peerErr)
	}
	if err := r.check(); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return conn, nil
}
