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
        NODE_ROOT / "experiments/xray-dataplane-fence/runtime_identity.go.txt",
        shared / "runtime_identity.go",
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
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/durable_counter_taint.go.txt",
        shared / "durable_counter_taint.go",
    )
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/durable_counter_taint_test.go.txt",
        shared / "durable_counter_taint_test.go",
    )
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/durable_meter_intent.go.txt",
        shared / "durable_meter_intent.go",
    )
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/durable_meter_intent_test.go.txt",
        shared / "durable_meter_intent_test.go",
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
    if err := xmeshdrain.RequireInboundCoverage(ctx); err != nil {
        common.Close(inboundLink.Writer)
        common.Interrupt(inboundLink.Reader)
        common.Close(outboundLink.Writer)
        common.Interrupt(outboundLink.Reader)
        return nil, nil, err
    }
    if xmeshdrain.IsTrackedInbound(ctx) {
        stopStream := func() {
            if sessionInbound.Conn != nil { _ = sessionInbound.Conn.Close() }
            common.Close(inboundLink.Writer)
            common.Interrupt(inboundLink.Reader)
            common.Close(outboundLink.Writer)
            common.Interrupt(outboundLink.Reader)
        }
        // A successfully authenticated VLESS session must not bypass user
        // metering because the policy disabled stats or registration failed.
        // Validate BEFORE Register/Dispatch, not only at final observation.
        if d.policy == nil || d.stats == nil {
            stopStream()
            return nil, nil, errors.New("experimental Xray: stats policy or manager unavailable")
        }
        level := d.policy.ForLevel(user.Level)
        if err := xmeshdrain.RequireMeteringCoverage(
            level.Stats.UserUplink, level.Stats.UserDownlink,
            func(direction string) bool {
                counter, err := d.stats.GetOrRegisterCounter(
                    "user>>>" + user.Email + ">>>traffic>>>" + direction)
                return err == nil && counter != nil
            }); err != nil {
            stopStream()
            return nil, nil, err
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
    if err := xmeshdrain.RequireInboundCoverage(ctx); err != nil {
        common.Close(outbound.Writer)
        common.Interrupt(outbound.Reader)
        return err
    }
    if subject := session.InboundFromContext(ctx); xmeshdrain.IsTrackedInbound(ctx) {
        stopStream := func() {
            if subject.Conn != nil { _ = subject.Conn.Close() }
            common.Close(outbound.Writer)
            common.Interrupt(outbound.Reader)
        }
        // DispatchLink is a separate UDP/XUDP/MUX meter path: it must
        // enforce the same bidirectional statistics policy before WrapLink.
        if d.policy == nil || d.stats == nil {
            stopStream()
            return errors.New("experimental Xray: stats policy or manager unavailable")
        }
        level := d.policy.ForLevel(subject.User.Level)
        if err := xmeshdrain.RequireMeteringCoverage(
            level.Stats.UserUplink, level.Stats.UserDownlink,
            func(direction string) bool {
                counter, err := d.stats.GetOrRegisterCounter(
                    "user>>>" + subject.User.Email + ">>>traffic>>>" + direction)
                return err == nil && counter != nil
            }); err != nil {
            stopStream()
            return err
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
                    link.Reader.(*buf.TimeoutWrapperReader).ExperimentalMayDeliver = func() bool {
                        return xmeshdrain.MayDeliverMeterRead(email)
                    }
                }
''',
    )
    # Install the counted-write gate on all three user statistics writer paths
    # (getLink uplink/downlink and DispatchLink downlink).
    for writer_path, direction in (
            ("inboundLink.Writer", "uplink"),
            ("outboundLink.Writer", "downlink"),
            ("link.Writer", "downlink")):
        source = replace_once(
            source,
            "\t\t\t\t\tWriter:  " + writer_path + ",\n",
            "\t\t\t\t\tWriter:  " + writer_path + ",\n"
            "\t\t\t\t\tExperimentalEmail: xmeshdrain.ScopedEmail(ctx),\n"
            "\t\t\t\t\tExperimentalDirection: " + '"' + direction + '"' + ",\n",
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
        '\tWriter  buf.Writer\n\tExperimentalEmail string\n'
        '\tExperimentalDirection string\n',
    )
    meter_source = replace_once(
        meter_source,
        '\tw.Counter.Add(int64(mb.Len()))\n\treturn w.Writer.WriteMultiBuffer(mb)',
        '''    if w.ExperimentalEmail != "" {
        if err := xmeshdrain.BeginMeterWrite(w.ExperimentalEmail,w.ExperimentalDirection); err != nil {
            buf.ReleaseMulti(mb)
            return err
        }
        defer xmeshdrain.EndMeterWrite(w.ExperimentalEmail,w.ExperimentalDirection)
    }
    if w.ExperimentalEmail != "" {
        audited, ok := w.Counter.(interface{ ExperimentalAddMetered(int64) int64 })
        if !ok {
            buf.ReleaseMulti(mb)
            panic("experimental Xray stats writer lacks trusted counter method")
        }
        audited.ExperimentalAddMetered(int64(mb.Len()))
    } else {
        w.Counter.Add(int64(mb.Len()))
    }
    return w.Writer.WriteMultiBuffer(mb)''',
    )
    meter_writer_file.write_text(meter_source, encoding="utf-8")

    # Xray's raw TCPConn.ReadFrom splice bypasses SizeStatWriter entirely:
    # upstream proxy.CopyRawConnIfExist increments statWriter.Counter.Add
    # AFTER a potentially unbounded kernel copy. Such traffic can outlive a
    # user fence and is not represented by Begin/EndMeterWrite. Both an
    # instrumented stat writer and an authenticated tracked inbound must
    # fail closed unless raw copy uses the buffered, gated writer path.
    proxy_file = root / "proxy/proxy.go"
    proxy_source = proxy_file.read_text(encoding="utf-8")
    proxy_source = replace_once(
        proxy_source,
        '\t"github.com/xtls/xray-core/app/dispatcher"\n',
        '\t"github.com/xtls/xray-core/app/dispatcher"\n'
        '\t"github.com/xtls/xray-core/app/xmeshdrain"\n',
    )
    proxy_source = replace_once(
        proxy_source,
        '\treaderConn, readCounter, _ := UnwrapRawConn(readerConn)\n'
        '\twriterConn, _, writeCounter := UnwrapRawConn(writerConn)\n',
        '''    readerConn, readCounter, _ := UnwrapRawConn(readerConn)
    // A monitored user can NEVER take the raw TCP splice fast path:
    // ReadFrom sends before its raw Counter.Add, outside the gated writer.
    // A late write after user revocation could escape without a meter.
    if scoped, ok := writer.(*dispatcher.SizeStatWriter); ok &&
        scoped.ExperimentalEmail != "" {
        if scoped.ExperimentalDirection != "downlink" || scoped.Counter == nil {
            return errors.New("experimental Xray: unsafe unmetered scoped raw writer")
        }
        if xmeshdrain.IsTrackedInbound(ctx) &&
            xmeshdrain.ScopedEmail(ctx) != scoped.ExperimentalEmail {
            return errors.New("experimental Xray: raw writer belongs to another user")
        }
        if readerConn == nil {
            return errors.New("experimental Xray: scoped raw reader is missing")
        }
        // A test must prove that real Vision/TLS sessions reached the
        // splice-PREPARABLE path, not merely the generic raw-copy function.
        // Inbound state 2 can transition to 1 while Vision decodes inner
        // TLS. We bypass the entire raw-copy loop, so only record a
        // candidate, never claim a physical kernel-splice operation.
        if runtime.GOOS == "linux" {
            rawWriter, _, _ := UnwrapRawConn(writerConn)
            if _, tcp := rawWriter.(*net.TCPConn); tcp {
                inbound := session.InboundFromContext(ctx)
                outbounds := session.OutboundsFromContext(ctx)
                candidate := inbound != nil && inbound.CanSpliceCopy != 3 && len(outbounds) > 0
                for _, ob := range outbounds {
                    if ob.CanSpliceCopy == 3 { candidate = false }
                }
                if candidate {
                    xmeshdrain.NoteBufferedSpliceCandidate(scoped.ExperimentalEmail)
                }
            }
        }
        // Keep the original writer (the instrumented SizeStatWriter).
        // Only readV -> WriteMultiBuffer can pass Begin/EndMeterWrite and the
        // trusted exact-alias counter update. No kernel splice is possible.
        return readV(ctx, buf.NewReader(readerConn), writer, timer, readCounter)
    }
    if xmeshdrain.IsTrackedInbound(ctx) {
        // A covered authenticated inbound without its mandatory wrapping
        // must never fall through to the upstream direct TCPConn.ReadFrom.
        return errors.New("experimental Xray: tracked raw copy missing stats writer")
    }
    writerConn, _, writeCounter := UnwrapRawConn(writerConn)
''',
    )
    proxy_file.write_text(proxy_source, encoding="utf-8")
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/splice_meter_test.go.txt",
        root / "proxy/xmesh_splice_meter_test.go",
    )

    # Patch ONLY the exact disposable Xray StatsService authority. Each user
    # Counter.Add/Set is serialized with the admission fence and checkpoint.
    # Never copy this instrumentation into the production Xray installer.
    counter_file = root / "app/stats/counter.go"
    counter = counter_file.read_text(encoding="utf-8")
    counter = replace_once(
        counter,
        "type Counter struct {\n\tvalue int64\n}",
        """type Counter struct {
    value int64
    experimentalName string
    experimentalAudit func(string, bool, func() int64) int64
    experimentalAddAudit func(string, int64, bool, func() int64, func() int64) int64
}""",
    )
    counter = replace_once(
        counter,
        "return atomic.SwapInt64(&c.value, newValue)",
        """if c.experimentalAudit != nil {
        return c.experimentalAudit(c.experimentalName, true, func() int64 {
            return atomic.SwapInt64(&c.value, newValue)
        })
    }
    return atomic.SwapInt64(&c.value, newValue)""",
    )
    counter = replace_once(
        counter,
        "return atomic.AddInt64(&c.value, delta)",
        """if c.experimentalAddAudit != nil && delta != 0 {
        return c.experimentalAddAudit(c.experimentalName, delta, false,
            func() int64 { return atomic.LoadInt64(&c.value) },
            func() int64 { return atomic.AddInt64(&c.value, delta) })
    }
    return atomic.AddInt64(&c.value, delta)""",
    )
    counter = replace_once(
        counter,
        "// Add implements stats.Counter.",
        """// ExperimentalAddMetered is the ONLY positive raw-byte update
// authorized by the pinned disposable instrumented Xray wrapper. Ordinary
// Counter.Add always carries trustedOrigin=false, even when another goroutine
// is writing this SAME user, alias and direction concurrently.
func (c *Counter) ExperimentalAddMetered(delta int64) int64 {
    if c.experimentalAddAudit == nil || delta < 0 {
        panic("experimental Xray trusted byte meter missing or invalid delta")
    }
    if delta == 0 {return c.Value()}
    return c.experimentalAddAudit(c.experimentalName, delta, true,
        func() int64 {return atomic.LoadInt64(&c.value)},
        func() int64 {return atomic.AddInt64(&c.value,delta)})
}

// Add implements stats.Counter.""",
    )
    counter_file.write_text(counter, encoding="utf-8")

    manager_file = root / "app/stats/stats.go"
    manager = manager_file.read_text(encoding="utf-8")
    manager = replace_once(
        manager,
        "\tcounters   map[string]*Counter\n",
        "\tcounters   map[string]*Counter\n\tcounterAudit func(string, bool, func() int64) int64\n"
        "\tcounterAddAudit func(string, int64, bool, func() int64, func() int64) int64\n",
    )
    manager = replace_once(
        manager,
        "// RegisterCounter implements stats.Manager.",
        """// Refuse binding after user counters have begun accumulating bytes.
func (m *Manager) SetExperimentalCounterMutationAudit(
    audit func(string, bool, func() int64) int64,
    addAudit func(string, int64, bool, func() int64, func() int64) int64,
) error {
    m.access.Lock()
    defer m.access.Unlock()
    if audit == nil || addAudit == nil || m.counterAudit != nil || len(m.counters) != 0 {
        return errors.New("Xray StatsService audit installed too late or twice")
    }
    m.counterAudit = audit
    m.counterAddAudit = addAudit
    return nil
}

// RegisterCounter implements stats.Manager.""",
    )
    manager = replace_once(
        manager,
        '\t"sync"\n',
        '\t"sync"\n\t"strings"\n',
    )
    manager = replace_once(
        manager,
        'func (m *Manager) UnregisterCounter(name string) error {\n\tm.access.Lock()\n\tdefer m.access.Unlock()\n',
        """func (m *Manager) UnregisterCounter(name string) error {
    m.access.Lock()
    defer m.access.Unlock()
    // Never discard/replace a raw per-user byte counter in the audited
    // experimental runtime. A new counter with the same name starts at 0
    // and would make a stable sampled meter silently undercount earlier use.
    if m.counterAudit != nil && strings.HasPrefix(name, "user>>>") &&
        (strings.HasSuffix(name, ">>>traffic>>>uplink") ||
         strings.HasSuffix(name, ">>>traffic>>>downlink")) {
        return errors.New("experimental Xray user byte counter cannot be unregistered")
    }
""",
    )
    if manager.count("\tc := new(Counter)\n") != 2:
        raise ValueError("Pinned StatsService changed counter registration paths")
    manager = manager.replace(
        "\tc := new(Counter)\n",
        "\tc := &Counter{experimentalName: name, experimentalAudit: m.counterAudit, experimentalAddAudit: m.counterAddAudit}\n",
    )
    manager_file.write_text(manager, encoding="utf-8")

    reader_file = root / "common/buf/io.go"
    reader_source = reader_file.read_text(encoding="utf-8")
    reader_source = replace_once(
        reader_source,
        '\t"os"\n',
        '\t"os"\n\t"sync"\n',
    )
    reader_source = replace_once(
        reader_source,
        '\tdone chan struct{}\n}',
        '\tdone chan struct{}\n'
        '\tExperimentalMu sync.Mutex\n'
        '\tExperimentalBegin func() bool\n'
        '\tExperimentalEnd func()\n'
        '\tExperimentalMayDeliver func() bool\n}',
    )
    reader_source = replace_once(
        reader_source,
        'func (r *TimeoutWrapperReader) ReadMultiBuffer() (MultiBuffer, error) {\n',
        '''func (r *TimeoutWrapperReader) ReadMultiBuffer() (MultiBuffer, error) {
    if r.ExperimentalBegin != nil {
        // One wrapper may not hand the same completed async buffer to two
        // competing callers. The read goroutine does NOT acquire this mutex;
        // it writes the result before closing done (a synchronization point).
        r.ExperimentalMu.Lock()
        defer r.ExperimentalMu.Unlock()
        if r.done != nil {
            <-r.done
            r.done = nil
            mb, err := r.mb, r.err
            r.mb, r.err = nil, nil
            if r.ExperimentalMayDeliver == nil || !r.ExperimentalMayDeliver() {
                ReleaseMulti(mb)
                return nil, io.EOF
            }
            return mb, err
        }
        if !r.ExperimentalBegin() {
            return nil, io.EOF
        }
        mb, err := r.Reader.ReadMultiBuffer()
        r.experimentalMeterAdd(mb)
        r.ExperimentalEnd()
        if r.ExperimentalMayDeliver == nil || !r.ExperimentalMayDeliver() {
            ReleaseMulti(mb)
            return nil, io.EOF
        }
        return mb, err
    }
''',
    )
    reader_source = replace_once(
        reader_source,
        'func (r *TimeoutWrapperReader) ReadMultiBufferTimeout(duration time.Duration) (MultiBuffer, error) {\n',
        '''func (r *TimeoutWrapperReader) ReadMultiBufferTimeout(duration time.Duration) (MultiBuffer, error) {
    if r.ExperimentalBegin != nil {
        // Serialize access to r.done, r.mb and r.err across concurrent
        // callers; otherwise two timeout waiters can both deliver one
        // completed buffer (or one waiter can overwrite the done channel).
        r.ExperimentalMu.Lock()
        defer r.ExperimentalMu.Unlock()
        if r.done == nil {
            if !r.ExperimentalBegin() {
                return nil, io.EOF
            }
            r.done = make(chan struct{})
            // An async timeout does not end the metered read. Its completion
            // is counted before done is closed, even if this call times out.
            go func() {
                r.mb, r.err = r.Reader.ReadMultiBuffer()
                r.experimentalMeterAdd(r.mb)
                r.ExperimentalEnd()
                close(r.done)
            }()
        }
        timeout := time.NewTimer(duration)
        defer timeout.Stop()
        select {
        case <-r.done:
            r.done = nil
            mb, err := r.mb, r.err
            r.mb, r.err = nil, nil
            if r.ExperimentalMayDeliver == nil || !r.ExperimentalMayDeliver() {
                ReleaseMulti(mb)
                return nil, io.EOF
            }
            return mb, err
        case <-timeout.C:
            return nil, nil
        }
    }
''',
    )
    reader_source = replace_once(
        reader_source,
        "type Writer interface {",
        """// Every experimental timed/direct user-buffer read needs the trusted
// StatsService counter method, not an ordinary Counter.Add shared with
// untracked background callers. ExperimentalBegin/End bound the operation.
func (r *TimeoutWrapperReader) experimentalMeterAdd(mb MultiBuffer) {
    audited, ok := r.Counter.(interface { ExperimentalAddMetered(int64) int64 })
    if !ok || audited == nil {
        panic("experimental Xray timed meter lacks trusted counter method")
    }
    audited.ExperimentalAddMetered(int64(mb.Len()))
}

type Writer interface {""",
    )
    reader_file.write_text(reader_source, encoding="utf-8")
    shutil.copyfile(
        NODE_ROOT / "experiments/xray-dataplane-fence/timeout_reader_test.go.txt",
        root / "common/buf/io_experimental_timeout_test.go",
    )

    subprocess.run(
        ["gofmt", "-w", str(shared / "xmeshdrain.go"),
         str(shared / "observed_checkpoint.go"),
         str(shared / "runtime_identity.go"),
         str(shared / "observed_checkpoint_test.go"),
         str(shared / "durable_fence.go"),
         str(shared / "durable_fence_test.go"),
         str(shared / "durable_counter_taint.go"),
         str(shared / "durable_counter_taint_test.go"),
         str(dispatcher_file), str(worker_file), str(mux_file),
         str(meter_writer_file), str(counter_file), str(manager_file),
         str(reader_file),
         str(root / "common/buf/io_experimental_timeout_test.go")],
        check=True,
        cwd=root,
    )
    print(f"Applied disposable Xray dataplane experiment to {PINNED_SHA} ONLY")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply-experiment.py <exact-pinned-xray-checkout>")
    run(Path(sys.argv[1]).resolve())
