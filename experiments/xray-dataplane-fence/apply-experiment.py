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
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/durable_fence.go.txt",
        shared / "durable_fence.go",
    )
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/durable_fence_test.go.txt",
        shared / "durable_fence_test.go",
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
    # The Dispatch() fast path is also metered by getLink(). Move admission
    # into getLink, after raw pipes exist but before user stat wrappers are
    # installed. Denied old UDP-association packets cannot then enter the
    # user counters via a second dispatch path.
    source = replace_once(
        source,
        'func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link) {',
        'func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link, error) {',
    )
    source = replace_once(
        source,
        '\tif user != nil && len(user.Email) > 0 {\n\t\tp := d.policy.ForLevel(user.Level)',
        '''    // Account-bearing VLESS user admission precedes ALL counter wrapping.
    if xmeshdrain.IsTrackedInbound(ctx) {
        stopStream := func() {
            if sessionInbound.Conn != nil { _ = sessionInbound.Conn.Close() }
            common.Close(inboundLink.Writer)
            common.Interrupt(inboundLink.Reader)
            common.Close(outboundLink.Writer)
            common.Interrupt(outboundLink.Reader)
        }
        if err := xmeshdrain.Register(ctx, sessionInbound.User.Email, stopStream); err != nil {
            stopStream()
            return nil, nil, err
        }
    }
    if user != nil && len(user.Email) > 0 {
        p := d.policy.ForLevel(user.Level)''',
    )
    source = replace_once(
        source,
        '\treturn inboundLink, outboundLink\n}',
        '\treturn inboundLink, outboundLink, nil\n}',
    )
    source = replace_once(
        source,
        '\tinbound, outbound := d.getLink(ctx)\n\tif !sniffingRequest.Enabled {',
        '''\tinbound, outbound, err := d.getLink(ctx)
    if err != nil { return nil, err }
    if !sniffingRequest.Enabled {''',
    )
    source = replace_once(
        source,
        '\toutbound = WrapLink(ctx, d.policy, d.stats, outbound)\n'
        '\tsniffingRequest := content.SniffingRequest',
        '''// Experimental link dispatch path: admission must be confirmed
    // BEFORE installing user stats wrappers. Otherwise a late UDP/XUDP
    // packet can increment the counter even when Register rejects it.
    if subject := session.InboundFromContext(ctx); xmeshdrain.IsTrackedInbound(ctx) {
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
    outbound = WrapLink(ctx, d.policy, d.stats, outbound)
    sniffingRequest := content.SniffingRequest''',
    )
    source = replace_once(
        source,
        'func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {\n',
        'func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {\n'
        '    // A returned inbound Process is not necessarily a finished route.\n'
        '    defer xmeshdrain.RouteFinish(ctx)\n',
    )
    # The upstream TimeoutWrapperReader charges a pending timeout read only
    # when a future ReadMultiBuffer() reaps it. Without that second call an
    # asynchronous read may finish AFTER a reported drain. For the scoped
    # experimental VLESS inbound, account the result inside the read worker
    # and track the worker until it finishes; leave every other Xray reader
    # unchanged.
    source = replace_once(
        source,
        '\t\t\t\tlink.Reader.(*buf.TimeoutWrapperReader).Counter = c\n',
        '''                link.Reader.(*buf.TimeoutWrapperReader).Counter = c
                if email := xmeshdrain.ScopedEmail(ctx); email != "" {
                    link.Reader.(*buf.TimeoutWrapperReader).ExperimentalBegin = func() bool {
                        return xmeshdrain.BeginMeterRead(email)
                    }
                    link.Reader.(*buf.TimeoutWrapperReader).ExperimentalEnd = func() {
                        xmeshdrain.EndMeterRead(email)
                    }
                }
''',
    )
    # Install the counted-write gate on all three user statistics writer paths
    # (getLink uplink/downlink and DispatchLink downlink).
    for writer_path in ("inboundLink.Writer", "outboundLink.Writer", "link.Writer"):
        source = replace_once(
            source,
            "\t\t\t\t\tWriter:  " + writer_path + ",\n",
            "\t\t\t\t\tWriter:  " + writer_path + ",\n"
            "\t\t\t\t\tExperimentalEmail: xmeshdrain.ScopedEmail(ctx),\n",
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
        '"github.com/xtls/xray-core/common/buf"\n',
        '"github.com/xtls/xray-core/app/xmeshdrain"\n'
        '\t"github.com/xtls/xray-core/common/buf"\n'
        '\tc "github.com/xtls/xray-core/common/ctx"\n',
    )
    mux = replace_once(
        mux,
        'func handle(ctx context.Context, s *Session, output buf.Writer) {\n',
        'func handle(ctx context.Context, s *Session, output buf.Writer) {\n'
        '    // The logical MUX stream owns its own lifecycle completion.\n'
        '    defer xmeshdrain.Finish(ctx)\n',
    )
    mux = replace_once(
        mux,
        '\tctx = session.SubContextFromMuxInbound(ctx)\n',
        '\tctx = session.SubContextFromMuxInbound(ctx)\n'
        '    // Parent Xray connection ID is shared by all MUX children.\n'
        '    // A unique child ID prevents false duplicate registration.\n'
        '    ctx = c.ContextWithID(ctx, session.NewID())\n',
    )
    mux_file.write_text(mux, encoding="utf-8")
    # Experimental post-meter writer barrier. Scoped writers cannot write or
    # count any bytes after the user's admission fence. Already started writes
    # remain tracked until their downstream WriteMultiBuffer returns.
    meter_writer_file = root / "app/dispatcher/stats.go"
    meter_source = meter_writer_file.read_text(encoding="utf-8")
    meter_source = replace_once(
        meter_source,
        '"github.com/xtls/xray-core/common"\n',
        '"github.com/xtls/xray-core/app/xmeshdrain"\n'
        '\t"github.com/xtls/xray-core/common"\n',
    )
    meter_source = replace_once(
        meter_source,
        '\tWriter  buf.Writer\n',
        '\tWriter  buf.Writer\n\tExperimentalEmail string\n',
    )
    meter_source = replace_once(
        meter_source,
        '\tw.Counter.Add(int64(mb.Len()))\n\treturn w.Writer.WriteMultiBuffer(mb)',
        '''    if w.ExperimentalEmail != "" {
        if err := xmeshdrain.BeginMeterWrite(w.ExperimentalEmail); err != nil {
            buf.ReleaseMulti(mb)
            return err
        }
        defer xmeshdrain.EndMeterWrite(w.ExperimentalEmail)
    }
    w.Counter.Add(int64(mb.Len()))
    return w.Writer.WriteMultiBuffer(mb)''',
    )
    meter_writer_file.write_text(meter_source, encoding="utf-8")

    reader_file = root / "common/buf/io.go"
    reader_source = reader_file.read_text(encoding="utf-8")
    reader_source = replace_once(
        reader_source,
        '\tdone chan struct{}\n}',
        '\tdone chan struct{}\n'
        '\tExperimentalBegin func() bool\n'
        '\tExperimentalEnd func()\n}',
    )
    reader_source = replace_once(
        reader_source,
        'func (r *TimeoutWrapperReader) ReadMultiBuffer() (MultiBuffer, error) {\n',
        '''func (r *TimeoutWrapperReader) ReadMultiBuffer() (MultiBuffer, error) {
    if r.ExperimentalBegin != nil {
        // A timed-out goroutine has already accounted the result before
        // closing done. Never count its bytes again on the next read.
        if r.done != nil {
            <-r.done
            r.done = nil
            return r.mb, r.err
        }
        if !r.ExperimentalBegin() {
            return nil, io.EOF
        }
        r.mb, r.err = r.Reader.ReadMultiBuffer()
        if r.Counter != nil { r.Counter.Add(int64(r.mb.Len())) }
        r.ExperimentalEnd()
        return r.mb, r.err
    }
''',
    )
    reader_source = replace_once(
        reader_source,
        'func (r *TimeoutWrapperReader) ReadMultiBufferTimeout(duration time.Duration) (MultiBuffer, error) {\n',
        '''func (r *TimeoutWrapperReader) ReadMultiBufferTimeout(duration time.Duration) (MultiBuffer, error) {
    if r.ExperimentalBegin != nil {
        if r.done == nil {
            if !r.ExperimentalBegin() {
                return nil, io.EOF
            }
            r.done = make(chan struct{})
            // The read may outlive the caller's timeout. Its metering and
            // completion must NOT outlive the tracked in-flight operation.
            go func() {
                r.mb, r.err = r.Reader.ReadMultiBuffer()
                if r.Counter != nil { r.Counter.Add(int64(r.mb.Len())) }
                r.ExperimentalEnd()
                close(r.done)
            }()
        }
        timeout := time.NewTimer(duration)
        defer timeout.Stop()
        select {
        case <-r.done:
            r.done = nil
            return r.mb, r.err
        case <-timeout.C:
            return nil, nil
        }
    }
''',
    )
    reader_file.write_text(reader_source, encoding="utf-8")
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/timeout_reader_test.go.txt",
        root / "common/buf/io_experimental_timeout_test.go",
    )

    subprocess.run(
        ["gofmt", "-w", str(shared / "xmeshdrain.go"),
         str(shared / "observed_checkpoint.go"),
         str(shared / "observed_checkpoint_test.go"),
         str(shared / "durable_fence.go"),
         str(shared / "durable_fence_test.go"),
         str(dispatcher_file), str(worker_file), str(mux_file),
         str(meter_writer_file), str(reader_file),
         str(root / "common/buf/io_experimental_timeout_test.go")],
        check=True,
        cwd=root,
    )
    print(f"Applied disposable Xray dataplane experiment to {PINNED_SHA} ONLY")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply-experiment.py <exact-pinned-xray-checkout>")
    run(Path(sys.argv[1]).resolve())
