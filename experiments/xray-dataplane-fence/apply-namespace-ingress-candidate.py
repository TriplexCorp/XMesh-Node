#!/usr/bin/env python3
"""Inject the dormant namespace frontend ONLY into a separate disposable Xray tree.

Never called by the normal attested meter build or product installation.
Require exact upstream commit + exact single patch anchors. The candidate
build is not a production artifact, even if all diagnostics pass.
"""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE / "apply-experiment.py"
spec = importlib.util.spec_from_file_location("base_xray_patch", BASE)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def replace_file(path, old, new):
    path.write_text(base.replace_once(path.read_text(), old, new))


def inject(root):
    shared = root / "app/xmeshdrain"
    peer = shared / "namespacepeer"
    peer.mkdir(mode=0o700, exist_ok=False)
    source = HERE.parent / "quota-v2-physical-stop/namespacepeer"
    for name in ("peer_linux.go", "listener_linux.go", "listener_manifest_linux.go"):
        shutil.copyfile(source / name, peer / name)
    # The compiled endpoint set has unique ports across the exact sealed
    # MAIN/CDN configuration. Transport's Xray hook uses the address/port
    # and cannot select another inbound tag by mutable environment.
    endpoint = peer / "candidate_endpoint_linux.go"
    endpoint.write_text('''//go:build linux && amd64

package namespacepeer

import (
    "errors"
    "net"
)

func (s *ListenerSet) AdoptEndpoint(address string, port int) (*net.TCPListener,error) {
    if s == nil { return nil,errors.New("missing sealed listener set") }
    for tag,item := range s.listeners {
        if item.token.Address == address && item.token.Port == port {
            return s.Adopt(tag,address,port)
        }
    }
    return nil,errors.New("no signed listener for requested endpoint")
}
''')
    candidate = shared / "namespace_ingress_candidate.go"
    shutil.copyfile(HERE / "namespace_ingress_candidate.go.txt", candidate)
    ingress = shared / "experimental_ingress.go"
    replace_file(ingress,
                 "func DialIngressMeter(ctx context.Context, user *protocol.MemoryUser) (net.Conn, error) {",
                 """func DialIngressMeter(ctx context.Context, user *protocol.MemoryUser) (net.Conn, error) {
    if NamespaceCandidateActive() {
        return dialNamespaceCandidateMeter(ctx,user)
    }""")
    hub = root / "transport/internet/tcp/hub.go"
    replace_file(hub, '"github.com/xtls/xray-core/common"',
                 '"github.com/xtls/xray-core/app/xmeshdrain"\n\t"github.com/xtls/xray-core/common"')
    replace_file(hub, "if streamSettings.FinalMask != nil {",
                 """if xmeshdrain.NamespaceCandidateActive() {
        if port == net.Port(0) || !address.Family().IsIPv4() || streamSettings.FinalMask != nil ||
           tls.ConfigFromStreamSettings(streamSettings) == nil ||
           reality.ConfigFromStreamSettings(streamSettings) != nil ||
           tcpSettings.HeaderSettings != nil ||
           (streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol) {
            return nil,errors.New("namespace candidate requires exact inherited TCP TLS transport")
        }
        listener,err = xmeshdrain.AdoptNamespaceCandidateListener(address.IP().String(),int(port))
    } else if streamSettings.FinalMask != nil {""")
    run = root / "main/run.go"
    replace_file(run, '"github.com/xtls/xray-core/common/cmdarg"',
                 '"github.com/xtls/xray-core/app/xmeshdrain"\n\t"github.com/xtls/xray-core/common/cmdarg"')
    replace_file(run, "configFiles := getConfigFilePath(true)",
                 """configFiles := getConfigFilePath(true)
    if xmeshdrain.NamespaceCandidateActive() &&
        (len(configFiles) != 1 || configFiles[0] != xmeshdrain.NamespaceCandidateConfigPath() ||
         configDir != "" || *format != "json") {
        return nil,errors.New("namespace candidate requires the exact independently sealed config")
    }""")
    subprocess.run(["gofmt", "-w", str(candidate), str(ingress), str(hub), str(run),
                    *[str(p) for p in peer.glob("*.go")]], check=True, cwd=root)


def main(root):
    if subprocess.check_output(["git","-C",str(root),"status","--porcelain"]).strip():
        raise ValueError("namespace candidate requires a clean disposable upstream checkout")
    base.run(root)
    inject(root)
    print("Applied separate disposable namespace candidate; NOT production release source")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply-namespace-ingress-candidate.py <exact-clean-upstream-checkout>")
    main(Path(sys.argv[1]).resolve())
