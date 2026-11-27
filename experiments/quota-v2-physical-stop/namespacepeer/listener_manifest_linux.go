//go:build linux && amd64

package namespacepeer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
)

const maxListenerManifest = 16 << 10
const maxSealedConfig = 16 << 20

// This matches the original Python canonical sorted-key manifest format.
type listenerRecord struct {
	Address     string `json:"address"`
	Cookie      string `json:"cookie"`
	Device      string `json:"device"`
	FD          int    `json:"fd"`
	Inode       string `json:"inode"`
	NetNSCookie string `json:"netnsCookie"`
	Port        int    `json:"port"`
	Tag         string `json:"tag"`
}

type listenerManifest struct {
	AuthoritySHA256 string           `json:"authoritySha256"`
	ConfigFD        int              `json:"configFd"`
	ConfigSHA256    string           `json:"configSha256"`
	Kind            string           `json:"kind"`
	Listeners       []listenerRecord `json:"listeners"`
	RosterSHA256    string           `json:"rosterSha256"`
	RuntimeID       string           `json:"runtimeId"`
	Version         int              `json:"version"`
}

type listenerInput struct {
	fd int
	token BoundListenerToken
}

type ListenerSet struct {
	mu         sync.Mutex
	manifestFD int
	manifestID identity
	raw        []byte
	configFD   int
	configID   identity
	configSHA  string
	listeners  map[string]listenerInput
	consumed   map[string]bool
}

func hashBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// OpenListeners validates a sealed manifest and actual sealed Xray config
// against independently pinned exact hashes. It does not listen or own any
// descriptor. A future launcher must still independently verify original
// authority, exact child ownership, socket transfer, and stop chain.
func OpenListeners(manifestFD, configFD int, runtimeID, rosterSHA, authoritySHA, configSHA string) (*ListenerSet, error) {
	for _, value := range []string{runtimeID, rosterSHA, authoritySHA, configSHA} {
		if !hex64.MatchString(value) {
			return nil, errors.New("independent exact runtime, roster, authority and config hashes required")
		}
	}
	if manifestFD < 3 || configFD < 3 || manifestFD == configFD {
		return nil, errors.New("separate sealed config and listener manifest FDs required")
	}
	raw, manifestID, err := readSealedLimit(manifestFD, maxListenerManifest)
	if err != nil {
		return nil, err
	}
	var m listenerManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	reencoded, err := json.Marshal(m)
	if err != nil || !bytes.Equal(raw, reencoded) || m.Kind != "xmesh.quota-v2.namespace-listener-inputs" ||
		m.Version != 1 || m.RuntimeID != runtimeID || m.RosterSHA256 != rosterSHA ||
		m.AuthoritySHA256 != authoritySHA || m.ConfigSHA256 != configSHA || m.ConfigFD != configFD ||
		len(m.Listeners) < 1 || len(m.Listeners) > 2 {
		return nil, errors.New("foreign or noncanonical sealed listener manifest")
	}
	configRaw, configID, err := readSealedLimit(configFD, maxSealedConfig)
	if err != nil || hashBytes(configRaw) != configSHA || configID == manifestID {
		return nil, errors.New("sealed listener config does not match independently pinned bytes")
	}
	var config struct {
		Inbounds []struct {
			Tag string `json:"tag"`
			Listen string `json:"listen"`
			Port int `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(configRaw, &config); err != nil || len(config.Inbounds) != len(m.Listeners) {
		return nil, errors.New("sealed config differs from exact listener roster")
	}
	type endpoint struct {
		address string
		port    int
	}
	expected := make(map[string]endpoint)
	for _, in := range config.Inbounds {
		if (in.Tag != "vless-main" && in.Tag != "vless-cdn") || in.Listen != "0.0.0.0" ||
			in.Port < 1 || in.Port > 65535 {
			return nil, errors.New("foreign sealed TLS endpoint")
		}
		if _, duplicate := expected[in.Tag]; duplicate {
			return nil, errors.New("duplicate sealed TLS inbound")
		}
		expected[in.Tag] = endpoint{in.Listen, in.Port}
	}
	set := &ListenerSet{manifestFD: manifestFD, manifestID: manifestID, raw: raw,
		configFD: configFD, configID: configID, configSHA: configSHA,
		listeners: make(map[string]listenerInput), consumed: make(map[string]bool)}
	fds := map[int]bool{manifestFD: true, configFD: true}
	ports := make(map[int]bool)
	cookies := make(map[uint64]bool)
	inodes := make(map[identity]bool)
	var netns uint64
	for i, record := range m.Listeners {
		ep, ok := expected[record.Tag]
		if !ok || ep != (endpoint{record.Address, record.Port}) ||
			(i > 0 && m.Listeners[i-1].Tag >= record.Tag) ||
			record.FD < 3 || fds[record.FD] || ports[record.Port] {
			return nil, errors.New("missing, duplicate or foreign listener scope")
		}
		id, err := inode(record.Device, record.Inode)
		if err != nil {
			return nil, err
		}
		cookie, err := uint64Field(record.Cookie)
		if err != nil {
			return nil, err
		}
		ns, err := uint64Field(record.NetNSCookie)
		if err != nil {
			return nil, err
		}
		if cookies[cookie] || inodes[id] || (netns != 0 && netns != ns) {
			return nil, errors.New("duplicate or foreign kernel listener identity")
		}
		token := BoundListenerToken{Address: record.Address, Port: record.Port, Device: id.dev,
			Inode: id.ino, Cookie: cookie, NetNSCookie: ns}
		if err := verifyListenerFD(record.FD, token, false); err != nil {
			return nil, err
		}
		fds[record.FD], ports[record.Port], cookies[cookie], inodes[id] = true, true, true, true
		netns = ns
		set.listeners[record.Tag] = listenerInput{record.FD, token}
	}
	if err := set.check(); err != nil {
		return nil, err
	}
	return set, nil
}

func (s *ListenerSet) check() error {
	raw, id, err := readSealedLimit(s.manifestFD, maxListenerManifest)
	if err != nil || id != s.manifestID || !bytes.Equal(raw, s.raw) {
		return errors.New("original sealed listener manifest changed")
	}
	config, id, err := readSealedLimit(s.configFD, maxSealedConfig)
	if err != nil || id != s.configID || hashBytes(config) != s.configSHA {
		return errors.New("original sealed listener config changed")
	}
	return nil
}

// Adopt takes an exact tag+endpoint from the independently selected config.
// It is one-shot even if adoption fails. The caller MUST terminate the
// child on any error rather than trying another socket or default listen.
func (s *ListenerSet) Adopt(tag, address string, port int) (*net.TCPListener, error) {
	if s == nil {
		return nil, errors.New("missing exact listener set")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.listeners[tag]
	if !ok || s.consumed[tag] || item.token.Address != address || item.token.Port != port {
		return nil, errors.New("foreign or previously consumed listener")
	}
	if err := s.check(); err != nil {
		return nil, err
	}
	s.consumed[tag] = true
	return AdoptTransferred(item.fd, item.token)
}
