#!/usr/bin/env python3
"""Fixed-action managed Xray transaction; never accepts executable/image/path input.
Raw, bounded stdout/stderr stays in root-only node logs. Only closed diagnostic
codes and exit status leave the node. Importable constructors are for tests.
"""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time

AGENT_VERSION = "control-v6.0.11"
VERSION = re.compile(r"v?([0-9]+\.[0-9]+\.[0-9]+(?:[._+-][A-Za-z0-9._+-]+)?)\Z")
IDENTITY = re.compile(r"sha256:[0-9a-f]{64}\Z")
OFFICIAL = "ghcr.io/xtls/xray-core:"
CODES = {
    'tls_resource_missing': 'TLS certificate/key unavailable in container',
    'geodata_missing': 'Required GeoData unavailable in container',
    'resource_permission': 'Container cannot read a required resource',
    'config_invalid': 'Xray rejected the active configuration',
    'disk_full': 'Node storage is full',
    'docker_unavailable': 'Local Docker daemon is unavailable',
    'download_failed': 'Docker image download failed; inspect private node diagnostic',
    'registry_unavailable': 'Official registry/network download failed',
    'image_not_found': 'Official release image not found',
    'registry_denied': 'Official registry denied download',
    'image_identity': 'Selected image identity/version does not match',
    'docker_validation': 'Docker could not execute isolated validation',
    'timeout': 'Operation exceeded its time limit',
    'prepare_failed': 'Cannot prepare managed container/resources',
    'start_failed': 'New managed container did not start',
    'health_failed': 'Container stability/listener health check failed',
    'pin_failed': 'Cannot persist verified image identity',
    'interrupted': 'Previous transaction was interrupted',
    'internal_error': 'Local updater failed; inspect root-only diagnostic logs',
}


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out); out.flush(); os.fsync(out.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class Failure(Exception):
    def __init__(self, code, rc=None):
        super().__init__(code)
        self.code, self.rc = code, rc


class Updater:
    def __init__(self, state=Path('/var/lib/xmesh-xray-sync'), name='xmesh-managed-xray',
                 docker=('docker',), emit=None, health_seconds=5):
        self.state, self.name, self.docker = Path(state), name, list(docker)
        self.emit = emit or (lambda event: print(json.dumps(event), flush=True))
        self.health_seconds = health_seconds
        self.stage, self.counter = 'preparing', 0
        self.record = {}

    def progress(self, stage, code=None, rc=None):
        self.stage = stage
        event = {'kind': 'progress', 'stage': stage}
        if code: event['code'] = code
        if rc is not None: event['exitCode'] = rc
        self.emit(event)

    def run(self, args, timeout=30, check=True, code='prepare_failed', limit=65536):
        """Drain both pipes continuously, retain a fixed bound, never log argv."""
        self.counter += 1
        capture = [bytearray(), bytearray()]
        process = subprocess.Popen(self.docker + list(args), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        def drain(stream, target):
            with stream:
                while True:
                    data = stream.read(8192)
                    if not data: break
                    target.extend(data[:max(0, limit - len(target))])
        threads = [threading.Thread(target=drain, args=(stream, capture[i]))
                   for i, stream in enumerate((process.stdout, process.stderr))]
        for thread in threads: thread.start()
        try:
            rc = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); process.wait(); rc = 124
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
            for thread in threads: thread.join()
        if rc < 0: rc = 128 - rc
        for suffix, data in zip(('stdout', 'stderr'), capture):
            path = self.logs / f'{self.counter:03}-{self.stage}.{suffix}'
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as out: out.write(data[:65536])
        retained=sorted([*self.logs.glob('*.stdout'),*self.logs.glob('*.stderr')])
        for old_log in retained[:-64]:old_log.unlink(missing_ok=True)
        if check and rc: raise Failure('timeout' if rc == 124 else code, rc)
        return rc, bytes(capture[0]), bytes(capture[1])

    def inspect(self, name):
        rc, out, _ = self.run(['inspect', name], check=False, limit=1048576)
        if rc: return None
        try: return json.loads(out)[0]
        except (ValueError, IndexError): raise Failure('prepare_failed') from None

    def save(self):
        atomic_json(self.journal, self.record)

    def cleanup_owned(self, name):
        item=self.inspect(name)
        if item and (item['Config'].get('Labels') or {}).get('io.xmesh.update-command')==str(self.command):
            self.run(['rm','-f',name],check=False)

    def resources(self, old):
        if old['HostConfig']['NetworkMode'] != 'host': raise Failure('prepare_failed')
        mounts, config = [], None
        for item in old['Mounts']:
            source, destination = item['Source'], item['Destination']
            if (any(c in destination for c in ',\n\r:') or
                destination in ('/', '/proc', '/sys', '/dev', '/var/run', '/run') or
                'docker.sock' in destination):raise Failure('prepare_failed')
            if item['Type']=='bind':
                if item.get('RW') or any(c in source for c in ',\n\r:') or source=='/' or not Path(source).exists():raise Failure('prepare_failed')
                mounts += ['--mount', f'type=bind,src={source},dst={destination},readonly']
                if destination=='/etc/xray/config.json':config=Path(source)
            elif item['Type']=='volume':
                # Official images declare config/log volumes automatically. Use
                # their existing names, contents and access mode, not fresh ones.
                name=item.get('Name','')
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name):raise Failure('prepare_failed')
                mode='' if item.get('RW') else ',readonly'
                mounts += ['--mount', f'type=volume,src={name},dst={destination}{mode}']
            else:raise Failure('prepare_failed')
        if not config or not config.is_file() or config.stat().st_size > 4*1024*1024: raise Failure('prepare_failed')
        # Confirm the bind source still represents the actual running config.
        snapshot = self.logs / 'active-config.private.json'
        self.run(['cp', self.name + ':/etc/xray/config.json', str(snapshot)])
        os.chmod(snapshot, 0o600)
        if snapshot.read_bytes() != config.read_bytes(): raise Failure('prepare_failed')
        try: self.config = json.loads(snapshot.read_bytes())
        except ValueError: raise Failure('config_invalid') from None
        self.record['configSha256'] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        for value in old['Config'].get('Env') or []:
            if value.startswith('XRAY_'): mounts += ['--env', value]
        working=old['Config'].get('WorkingDir')
        if working:mounts+=['--workdir',working]
        return mounts

    def health(self, name, identity):
        deadline = time.monotonic() + self.health_seconds
        pid = None
        while True:
            item = self.inspect(name)
            if (not item or item['Image'] != identity or not item['State']['Running'] or
                item.get('RestartCount', 0) != (self.record.get('oldRestartCount',0) if item['Id']==self.record.get('oldContainerId') else 0) or item['State'].get('Health', {}).get('Status') == 'unhealthy'):
                raise Failure('health_failed')
            current_pid = item['State'].get('Pid')
            if pid is not None and current_pid != pid: raise Failure('health_failed')
            pid = current_pid
            if time.monotonic() >= deadline: break
            time.sleep(.5)
        for inbound in self.config.get('inbounds', []):
            transport = inbound.get('streamSettings', {}).get('network', 'tcp')
            networks = inbound.get('settings', {}).get('network', 'tcp,udp')
            port = inbound.get('port')
            if transport in ('quic', 'hysteria', 'hysteria2') or 'tcp' not in networks or not isinstance(port, int): continue
            host = inbound.get('listen') or '127.0.0.1'
            host = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(host, host)
            if not isinstance(host, str) or host.startswith('/'): continue
            try:
                with socket.create_connection((host, port), timeout=2): pass
            except OSError: raise Failure('health_failed') from None

    @staticmethod
    def validation_code(output, rc):
        text = output.lower()
        if b'permission denied' in text: return 'resource_permission'
        if any(x in text for x in (b'geosite', b'geoip', b'geodata')): return 'geodata_missing'
        if any(x in text for x in (b'certificate', b'fullchain', b'private key', b'.pem')) and any(x in text for x in (b'no such file', b'failed to', b'cannot')): return 'tls_resource_missing'
        return 'docker_validation' if rc in (125, 126, 127) else 'config_invalid'

    def rollback(self):
        self.progress('rolling_back')
        backup = self.inspect(self.backup)
        if not backup or backup['Id'] != self.record['oldContainerId']: raise Failure('interrupted')
        current = self.inspect(self.name)
        if current:
            if current['Config'].get('Labels', {}).get('io.xmesh.update-command') != str(self.command): raise Failure('interrupted')
            self.run(['rm', '-f', self.name])
        self.run(['rename', self.backup, self.name])
        self.run(['update', '--restart=' + self.record['oldRestart'], self.name])
        self.run(['start', self.name], code='start_failed')
        self.health(self.name, self.record['oldImage'])
        if 'oldPin' in self.record:
            for filename, value in self.record['oldPin'].items():
                path = self.state / filename
                if value is None: path.unlink(missing_ok=True)
                else: atomic_json(path, value) if filename.endswith('.json') else self.write_pin(path, value)
        self.cleanup_owned(self.next)

    @staticmethod
    def write_pin(path, value):
        fd, temporary = tempfile.mkstemp(prefix='.pin-', dir=path.parent)
        with os.fdopen(fd, 'w') as out: out.write(value); out.flush(); os.fsync(out.fileno())
        os.replace(temporary, path)

    def recover_pending(self):
        # A lease can expire while a node is rebooting. Reconcile its interrupted
        # switch before a later command is allowed to replace the live container.
        for directory in (self.state/'updates').iterdir():
            journal=directory/'transaction.json'
            if directory==self.logs or directory.is_symlink() or not directory.name.isdigit() or not journal.is_file():continue
            record=json.loads(journal.read_bytes())
            if 'result' in record:continue
            prior=copy.copy(self);prior.logs=directory;prior.journal=journal;prior.record=record
            prior.command=int(directory.name);prior.target=record['version'];prior.emit=lambda event:None
            prior.next=f'{self.name}.next-{prior.command}';prior.backup=f'{self.name}.rollback-{prior.command}'
            result=prior.recover()
            if result.get('rollback')=='rollback_failed':raise Failure('prepare_failed')

    def prune_private_logs(self):
        directories=sorted((p for p in (self.state/'updates').iterdir() if p.is_dir() and not p.is_symlink() and p.name.isdigit()),key=lambda p:int(p.name))
        for directory in directories[:-10]:
            journal=directory/'transaction.json'
            if not journal.exists() or 'result' not in json.loads(journal.read_bytes()):continue
            for path in [*directory.glob('*.stdout'),*directory.glob('*.stderr'),directory/'active-config.private.json']:
                path.unlink(missing_ok=True)

    def perform(self, version, command):
        match = VERSION.fullmatch(version)
        if not match or not isinstance(command, int) or command <= 0: raise ValueError('invalid command')
        self.command, self.target = command, match[1]
        self.next, self.backup = f'{self.name}.next-{command}', f'{self.name}.rollback-{command}'
        directory = self.state / 'updates'; directory.mkdir(mode=0o700, exist_ok=True)
        self.logs = directory / str(command); self.logs.mkdir(mode=0o700, exist_ok=True)
        self.journal = self.logs / 'transaction.json'
        # The node reconciliation service uses exactly this lock.
        with (self.state / 'lock').open('a') as lock:
            deadline=time.monotonic()+10
            while True:
                try: fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline: raise Failure('prepare_failed')
                    time.sleep(.2)
            self.recover_pending()
            self.prune_private_logs()
            if self.journal.exists():
                self.record = json.loads(self.journal.read_bytes())
                if self.record['version'] != self.target: raise ValueError('command target changed')
                if 'result' in self.record: self.emit(self.record['result']); return self.record['result']
                return self.recover()
            self.record = {'version': self.target, 'phase': 'preparing'}
            self.save()
            try:
                self.execute()
                result = {'kind': 'result', 'success': True, 'stage': 'completed', 'code': 'ok',
                          'detail': f'Xray {self.target} installed; image identity and runtime verified'}
            except Failure as failure:
                result = self.failed(failure)
            except Exception:
                result = self.failed(Failure('internal_error'))
            self.record['result'] = result
            try:self.save()
            except OSError:
                if result['success']:
                    self.record['phase']='switching';result=self.failed(Failure('pin_failed'))
                result['detail']=(result['detail']+'; result journal write failed')[:256]
            self.emit(result); return result

    def recover(self):
        # An interrupted switch is rolled back before any new pull or deployment.
        try:
            old = self.inspect(self.name)
            if self.record.get('phase') == 'preparing' and not self.record.get('oldContainerId'):
                result=self.error_result(Failure('interrupted'),'unchanged');self.record['result']=result;self.save();self.emit(result);return result
            if self.record.get('phase')=='committed' and old and old['Image']==self.record.get('newImage'):
                self.config=json.loads((self.logs/'active-config.private.json').read_bytes());self.health(self.name,self.record['newImage'])
                result={'kind':'result','success':True,'stage':'completed','code':'ok','detail':f'Xray {self.target} installed; image identity and runtime verified'}
                self.record['result']=result;self.save();self.emit(result);return result
            if old and old['Id'] == self.record.get('oldContainerId'):
                if not old['State']['Running']: self.run(['start', self.name])
                self.config = json.loads((self.logs / 'active-config.private.json').read_bytes())
                self.health(self.name, self.record['oldImage'])
                restored = 'unchanged'
            else:
                self.config = json.loads((self.logs / 'active-config.private.json').read_bytes())
                self.rollback(); restored = 'rolled_back'
            self.cleanup_owned(self.next)
            result = self.error_result(Failure('interrupted'), restored)
        except Exception:
            result = self.error_result(Failure('interrupted'), 'rollback_failed')
        self.record['result'] = result; self.save(); self.emit(result); return result

    def execute(self):
        self.progress('preparing')
        old = self.inspect(self.name)
        if not old or not old['State']['Running']: raise Failure('prepare_failed')
        self.record.update(oldImage=old['Image'], oldContainerId=old['Id'],
                           oldRestart=old['HostConfig']['RestartPolicy']['Name'] or 'no', oldRestartCount=old.get('RestartCount',0))
        if not IDENTITY.fullmatch(old['Image']): raise Failure('image_identity')
        mounts = self.resources(old)
        self.record['oldPin'] = {name: (json.loads((self.state / name).read_bytes()) if name.endswith('.json') else (self.state / name).read_text()) if (self.state / name).exists() else None for name in ('pinned-image', 'pinned-release.json')}
        self.save()
        image = OFFICIAL + self.target
        self.progress('downloading')
        for attempt in range(2):
            rc, out, err = self.run(['pull', image], timeout=115, check=False)
            if not rc: break
            if attempt == 1:
                message=(out+err).lower()
                if b'no space left' in message:code='disk_full'
                elif any(x in message for x in (b'cannot connect to the docker daemon',b'is the docker daemon running')):code='docker_unavailable'
                elif any(x in message for x in (b'manifest unknown',b'manifest not found')):code='image_not_found'
                elif any(x in message for x in (b'unauthorized',b'denied',b'forbidden')):code='registry_denied'
                elif rc==124 or any(x in message for x in (b'connection refused',b'no such host',b'network is unreachable',b'timeout',b'deadline exceeded',b'tls handshake',b'502',b'503',b'504')):code='registry_unavailable'
                else:code='download_failed'
                raise Failure(code, rc)
            time.sleep(4)
        new = self.inspect(image)
        if not new or not IDENTITY.fullmatch(new['Id']): raise Failure('image_identity')
        identity = new['Id']; self.record['newImage'] = identity; self.save()
        rc, out, _ = self.run(['run', '--rm', '--network', 'none', '--entrypoint', 'xray', identity, 'version'], code='image_identity')
        tokens=out.splitlines()[0].split() if out else []
        if len(tokens)<2 or tokens[0]!=b'Xray' or tokens[1]!=self.target.encode():raise Failure('image_identity')
        self.progress('validating')
        sandbox = ['--user', '0:0', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--entrypoint', 'xray']
        validation = self.next + '.validate'
        try:
            rc, out, err = self.run(['run', '--rm', '--name', validation, '--label', f'io.xmesh.update-command={self.command}', '--network', 'none'] + sandbox + mounts + [identity, 'run', '-test', '-config', '/etc/xray/config.json'], timeout=25, check=False)
        finally:
            self.cleanup_owned(validation)
        if rc: raise Failure('timeout' if rc == 124 else self.validation_code(out + err, rc), rc)
        self.progress('staging')
        self.run(['create', '--name', self.next, '--label', f'io.xmesh.update-command={self.command}', '--restart', self.record['oldRestart'], '--network', 'host'] + sandbox + mounts + [identity, 'run', '-config', '/etc/xray/config.json'])
        candidate = self.inspect(self.next)
        if not candidate or candidate['Image'] != identity: raise Failure('image_identity')
        self.record['phase'] = 'switching'; self.save()
        self.progress('starting')
        self.run(['update', '--restart=no', self.name])
        self.run(['stop', '--time', '10', self.name], timeout=15)
        self.run(['rename', self.name, self.backup])
        self.run(['rename', self.next, self.name])
        self.run(['start', self.name], code='start_failed')
        self.progress('health_check')
        self.health(self.name, identity)
        self.progress('committing')
        try:
            self.write_pin(self.state / 'pinned-image', image + '\n')
            atomic_json(self.state / 'pinned-release.json', {'image': image, 'imageId': identity})
            self.record['phase'] = 'committed'; self.save()
        except OSError:
            self.record['phase'] = 'switching'
            raise Failure('pin_failed') from None
        # Keep the latest stopped rollback container, pinning its exact cached ID.
        previous = self.state / 'previous-update.json'
        with contextlib.suppress(OSError, ValueError, Failure):
            if previous.exists():
                prior = json.loads(previous.read_bytes()).get('command')
                if isinstance(prior, int) and prior != self.command:
                    name=f'{self.name}.rollback-{prior}'
                    item=self.inspect(name)
                    if item and item['Id']==json.loads(previous.read_bytes()).get('backupId'):
                        self.run(['rm', name], check=False)
            atomic_json(previous, {'command': self.command,'backupId':self.record['oldContainerId']})

    def error_result(self, failure, recovery):
        detail = f'{self.stage}: {CODES[failure.code]}'
        if failure.rc is not None: detail += f' (exit {failure.rc})'
        detail += '; ' + {'unchanged': 'old Xray unchanged', 'rolled_back': 'previous image restored and healthy', 'rollback_failed': 'ROLLBACK FAILED; operator action required'}[recovery]
        return {'kind': 'result', 'success': False, 'stage': self.stage, 'code': failure.code,
                'exitCode': failure.rc, 'rollback': recovery, 'detail': detail[:256]}

    def failed(self, failure):
        failed_stage = self.stage
        recovery = 'unchanged'
        if self.record.get('phase') == 'switching':
            try:
                current = self.inspect(self.name)
                if current and current['Id'] == self.record['oldContainerId']:
                    self.run(['update', '--restart=' + self.record['oldRestart'], self.name])
                    if not current['State']['Running']: self.run(['start', self.name])
                    self.health(self.name, self.record['oldImage'])
                else:
                    self.rollback()
                recovery = 'rolled_back'
            except Exception: recovery = 'rollback_failed'
        self.stage = failed_stage
        self.cleanup_owned(self.next)
        return self.error_result(failure, recovery)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True)
    parser.add_argument('--command-id', required=True, type=int)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = Updater().perform(args.version, args.command_id)
    except Exception:
        result = {'kind': 'result', 'success': False, 'stage': 'preparing',
                  'code': 'internal_error', 'detail': 'preparing: local update journal unavailable; old Xray not intentionally changed'}
        print(json.dumps(result), flush=True)
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
