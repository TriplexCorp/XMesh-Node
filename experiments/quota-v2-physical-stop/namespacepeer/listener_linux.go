//go:build linux && amd64

package namespacepeer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// BoundListenerToken is the exact independently measured kernel identity
// of an exclusive signed IPv4 endpoint. The supervisor must authenticate
// the endpoint, verify direct-child inheritance, release its own FD, and
// enforce the independent stop-only chain BEFORE calling AdoptTransferred.
// This package does not implement those gates or issue traffic authority.
type BoundListenerToken struct {
	Address     string
	Port        int
	Device      uint64
	Inode       uint64
	Cookie      uint64
	NetNSCookie uint64
}

const (
	soCookie      = 57
	soNetNSCookie = 71
	soProtocol    = 38
	soBindDevice  = 25
	ipFreebind    = 15
	ipTransparent = 19
	soReusePort   = 15
)

func socketOptionBytes(fd, level, option, size int) ([]byte, error) {
	if size <= 0 || size > 64 {
		return nil, errors.New("invalid bounded socket option size")
	}
	value := make([]byte, size)
	length := uint32(size)
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level),
		uintptr(option), uintptr(unsafe.Pointer(&value[0])),
		uintptr(unsafe.Pointer(&length)), 0)
	if e != 0 {
		return nil, e
	}
	if length > uint32(size) {
		return nil, errors.New("oversized kernel socket option")
	}
	return value[:length], nil
}

func socketCookie(fd, option int) (uint64, error) {
	raw, err := socketOptionBytes(fd, syscall.SOL_SOCKET, option, 8)
	if err != nil {
		return 0, err
	}
	if len(raw) != 8 || binary.LittleEndian.Uint64(raw) == 0 {
		return 0, errors.New("missing exact kernel socket cookie")
	}
	return binary.LittleEndian.Uint64(raw), nil
}

func verifyListenerFD(fd int, token BoundListenerToken, listening bool) error {
	ip := net.ParseIP(token.Address)
	if fd < 3 || ip == nil || ip.To4() == nil || ip.To4().String() != token.Address ||
		token.Port < 1 || token.Port > 65535 || token.Device == 0 || token.Inode == 0 ||
		token.Cookie == 0 || token.NetNSCookie == 0 || os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("exact canonical bound listener identity required")
	}
	expectedPhase := 0
	if listening {
		expectedPhase = 1
	}
	for _, option := range [][3]int{
		{syscall.SOL_SOCKET, soDomain, syscall.AF_INET},
		{syscall.SOL_SOCKET, syscall.SO_TYPE, syscall.SOCK_STREAM},
		{syscall.SOL_SOCKET, soProtocol, syscall.IPPROTO_TCP},
		{syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 0},
		{syscall.SOL_SOCKET, soReusePort, 0},
		{syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN, expectedPhase},
		{syscall.IPPROTO_IP, ipFreebind, 0},
		{syscall.IPPROTO_IP, ipTransparent, 0},
	} {
		got, err := syscall.GetsockoptInt(fd, option[0], option[1])
		if err != nil || got != option[2] {
			return fmt.Errorf("unexpected bound socket option %d/%d: %d %v", option[0], option[1], got, err)
		}
	}
	device, err := socketOptionBytes(fd, syscall.SOL_SOCKET, soBindDevice, 16)
	if err != nil {
		return err
	}
	for _, b := range device {
		if b != 0 {
			return errors.New("unexpected socket device override")
		}
	}
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFSOCK ||
		uint64(before.Dev) != token.Device || uint64(before.Ino) != token.Inode {
		return errors.New("listener descriptor differs from original kernel inode")
	}
	sa, err := syscall.Getsockname(fd)
	addr, ok := sa.(*syscall.SockaddrInet4)
	if err != nil || !ok || addr.Port != token.Port || net.IP(addr.Addr[:]).String() != token.Address {
		return errors.New("listener differs from signed IPv4 address and port")
	}
	if _, err := syscall.Getpeername(fd); err != syscall.ENOTCONN {
		return errors.New("listener is a connected or invalid socket")
	}
	cookie, err := socketCookie(fd, soCookie)
	if err != nil || cookie != token.Cookie {
		return errors.New("listener socket cookie differs")
	}
	ns, err := socketCookie(fd, soNetNSCookie)
	if err != nil || ns != token.NetNSCookie {
		return errors.New("listener network namespace cookie differs")
	}
	if syscall.Fstat(fd, &after) != nil || statID(&before) != statID(&after) {
		return errors.New("listener descriptor changed")
	}
	return nil
}

// AdoptTransferred is the dormant Go transport adapter, not an authority
// gate. Ownership of fd transfers on entry; on all errors it closes it.
// It never creates, binds or dials an Internet socket. net.FileListener
// duplicates the descriptor INSIDE the owned child, so the input copy is
// immediately closed and only the pollable Go listener survives. The
// supervisor must read back the final kernel socket identity without
// duplicating it, not assume the former FD number is still allocated.
func AdoptTransferred(fd int, token BoundListenerToken) (*net.TCPListener, error) {
	if fd < 3 {
		return nil, errors.New("invalid owned listener FD")
	}
	file := os.NewFile(uintptr(fd), "xmesh-owned-prebound-listener")
	if file == nil {
		return nil, errors.New("invalid owned listener file")
	}
	defer file.Close()
	if err := verifyListenerFD(fd, token, false); err != nil {
		return nil, err
	}
	if err := syscall.Listen(fd, 128); err != nil {
		return nil, err
	}
	if err := verifyListenerFD(fd, token, true); err != nil {
		return nil, err
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	tcp, ok := listener.(*net.TCPListener)
	if !ok {
		listener.Close()
		return nil, errors.New("inherited listener is not Go TCP transport")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		tcp.Close()
		return nil, err
	}
	var proof error
	if err := raw.Control(func(n uintptr) { proof = verifyListenerFD(int(n), token, true) }); err != nil {
		tcp.Close()
		return nil, err
	}
	if proof != nil {
		tcp.Close()
		return nil, proof
	}
	// Close the original before the caller can begin accepting. An error
	// cannot leave the newly adopted listener alive.
	if err := file.Close(); err != nil {
		tcp.Close()
		return nil, err
	}
	return tcp, nil
}
