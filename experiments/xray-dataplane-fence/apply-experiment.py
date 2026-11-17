#!/usr/bin/env python3
"""Patch ONLY a disposable checkout of EXACT Xray-core 26.10.31.

Never patches production Xray; never enables quota refunds. Fail closed on
unexpected upstream text, tag movement, missing local experiment files.
"""
from pathlib import Path
import shutil
import subprocess
import sys

PINNED_SHA = "a4a3dff5b20c2faae567b742c172c7b95e75c083"
NODE_ROOT = Path(__file__).resolve().parents[2]


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Pinned upstream patch anchor missing or ambiguous: " + old[:90])
    return text.replace(old, new)


def run(root: Path):
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual != PINNED_SHA:
        raise ValueError(f"Refuse changed upstream Xray: expected {PINNED_SHA}, got {actual}")
    if not (root / "app" / "dispatcher" / "default.go").is_file():
        raise ValueError("Not an Xray source checkout")
    shared = root / "app" / "xmeshdrain"
    shared.mkdir(mode=0o700, exist_ok=False)
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/xmeshdrain.go.txt",
        shared / "xmeshdrain.go",
    )
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/xmeshdrain_test.go.txt",
        shared / "xmeshdrain_test.go",
    )

    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/observed_checkpoint.go.txt",
        shared / "observed_checkpoint.go",
    )
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/observed_checkpoint_test.go.txt",
        shared / "observed_checkpoint_test.go",
    )

    dispatcher_file = root / "app/dispatcher/default.go"
    source = dispatcher_file.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '"github.com/xtls/xray-core/common"\n',
        '"github.com/xtls/xray-core/app/xmeshdrain"\n'
        '\t"github.com/xtls/xray-core/common"\n',
    )
    source = replace_once(
        source,
        '\td.stats = sm\n\treturn nil\n}',
        '\td.stats = sm\n    xmeshdrain.BindStatsManager(sm)\n\treturn nil\n}',
    )
    source = replace_once(
        source,
        '\tinbound, outbound := d.getLink(ctx)\n\tif !sniffingRequest.Enabled {',
        '''\tinbound, outbound := d.getLink(ctx)
    // Experimental: register each authenticated TCP session before any link
    // is returned to the inbound. Registration is atomic with fence.
    if subject := session.InboundFromContext(ctx); subject != nil &&
        subject.User != nil && subject.Tag == "vless-share" {
        stopStream := func() {
            if subject.Conn != nil { _ = subject.Conn.Close() }
            common.Close(inbound.Writer)
            common.Interrupt(inbound.Reader)
            common.Close(outbound.Writer)
            common.Interrupt(outbound.Reader)
        }
        if err := xmeshdrain.Register(ctx, subject.User.Email, stopStream); err != nil {
            stopStream()
            return nil, err
        }
    }
    if !sniffingRequest.Enabled {''',
    )
    source = replace_once(
        source,
        '\toutbound = WrapLink(ctx, d.policy, d.stats, outbound)\n'
        '\tsniffingRequest := content.SniffingRequest',
        '''\toutbound = WrapLink(ctx, d.policy, d.stats, outbound)
    // Experimental link dispatch path (including non-TCP transports):
    // a failed admission never proceeds to a live outbound route.
    if subject := session.InboundFromContext(ctx); subject != nil &&
        subject.User != nil && subject.Tag == "vless-share" {
        stopStream := func() {
            if subject.Conn != nil { _ = subject.Conn.Close() }
            common.Close(outbound.Writer)
            common.Interrupt(outbound.Reader)
        }
        if err := xmeshdrain.Register(ctx, subject.User.Email, stopStream); err != nil {
            stopStream()
            return err
        }
    }
    sniffingRequest := content.SniffingRequest''',
    )
    source = replace_once(
        source,
        'func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {\n',
        'func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {\n'
        '    // A returned inbound Process is not necessarily a finished route.\n'
        '    defer xmeshdrain.RouteFinish(ctx)\n',
    )
    dispatcher_file.write_text(source, encoding="utf-8")

    worker_file = root / "app/proxyman/inbound/worker.go"
    worker = worker_file.read_text(encoding="utf-8")
    worker = replace_once(
        worker,
        '"github.com/xtls/xray-core/common"\n',
        '"github.com/xtls/xray-core/app/xmeshdrain"\n'
        '\t"github.com/xtls/xray-core/common"\n',
    )
    worker = replace_once(
        worker,
        '''\tcancel()
\tconn.Close()
}

func (w *tcpWorker) Proxy() proxy.Inbound {''',
        '''\tcancel()
\tconn.Close()
    // Callback reached after the authenticated inbound Process completed.
    // This is NOT proven to flush the entire Xray dataplane meter.
    xmeshdrain.Finish(ctx)
}

func (w *tcpWorker) Proxy() proxy.Inbound {''',
    )
    worker = replace_once(
        worker,
        '''\t\t\tconn.Close()
\t\t\t// conn not removed by checker TODO may be lock worker here is better''',
        '''\t\t\tconn.Close()
            xmeshdrain.Finish(ctx)
\t\t\t// conn not removed by checker TODO may be lock worker here is better''',
    )
    worker = replace_once(
        worker,
        '''\tif err := conn.Close(); err != nil {
\t\terrors.LogInfoInner(ctx, err, "failed to close connection")
\t}
}

func (w *dsWorker) Proxy() proxy.Inbound {''',
        '''\tif err := conn.Close(); err != nil {
\t\terrors.LogInfoInner(ctx, err, "failed to close connection")
\t}
    xmeshdrain.Finish(ctx)
}

func (w *dsWorker) Proxy() proxy.Inbound {''',
    )
    worker_file.write_text(worker, encoding="utf-8")

    # MUX child streams inherit their physical parent's context ID by default.
    # Assign each authenticated logical stream its own runtime ID before
    # Dispatch(), and finish its gate only after the MUX output pump ended.
    # These changes are exercised only by the disposable, exact-pinned Xray.
    mux_file = root / "common/mux/server.go"
    mux = mux_file.read_text(encoding="utf-8")
    mux = replace_once(
        mux,
        '"github.com/xtls/xray-core/common/buf"\\n',
        '"github.com/xtls/xray-core/app/xmeshdrain"\\n'
        '\\t"github.com/xtls/xray-core/common/buf"\\n'
        '\\tc "github.com/xtls/xray-core/common/ctx"\\n',
    )
    mux = replace_once(
        mux,
        'func handle(ctx context.Context, s *Session, output buf.Writer) {\\n',
        'func handle(ctx context.Context, s *Session, output buf.Writer) {\\n'
        '    // The logical MUX stream owns its own lifecycle completion.\\n'
        '    defer xmeshdrain.Finish(ctx)\\n',
    )
    mux = replace_once(
        mux,
        '\\tctx = session.SubContextFromMuxInbound(ctx)\\n',
        '\\tctx = session.SubContextFromMuxInbound(ctx)\\n'
        '    // Parent Xray connection ID is shared by all MUX children.\\n'
        '    // A unique child ID prevents false duplicate registration.\\n'
        '    ctx = c.ContextWithID(ctx, session.NewID())\\n',
    )
    mux_file.write_text(mux, encoding="utf-8")
    subprocess.run(
        ["gofmt", "-w", str(shared / "xmeshdrain.go"),
         str(shared / "observed_checkpoint.go"),
         str(shared / "observed_checkpoint_test.go"),
         str(dispatcher_file), str(worker_file), str(mux_file)],
        check=True,
        cwd=root,
    )
    print(f"Applied disposable Xray dataplane experiment to {PINNED_SHA} ONLY")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply-experiment.py <exact-pinned-xray-checkout>")
    run(Path(sys.argv[1]).resolve())
