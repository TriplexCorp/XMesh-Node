#!/usr/bin/env python3
"""Actual foreign mount namespace and exact detached original Unix peer."""
import errno
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/quota-v2-physical-stop'))
import public_tls_route_mount as mounts
import public_tls_peer_identity as peers


METER = r"""
import os, socket, stat, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
subprocess.run(['mount','-t','tmpfs','-o','mode=0700,nosuid,nodev,noexec','tmpfs',str(root)],check=True,timeout=5)
directory = root / 'only-meter'
directory.mkdir(mode=0o700)
if sys.argv[2] == 'structure':
    os.mknod(directory / 'vless-main',stat.S_IFSOCK | 0o600)
    print('foreign_meter_ready',flush=True)
    assert sys.stdin.readline() == 'stop\n'
    sys.exit(0)
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
    sock.bind(str(directory / 'vless-main'))
    (directory / 'vless-main').chmod(0o600)
    sock.listen(1)
    print('foreign_meter_ready',flush=True)
    conn,_ = sock.accept()
    with conn:
        assert conn.recv(1) == b'X'
        conn.sendall(b'Y')
    assert sys.stdin.readline() == 'stop\n'
"""


class ForeignMountTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest('root mount namespace qualification required')
        self.temp = tempfile.TemporaryDirectory(prefix='xmesh-foreign-mount-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.local = os.readlink('/proc/self/ns/mnt')
        self.structure = os.environ.get('XMESH_TEST_FOREIGN_MOUNT_STRUCTURE') == '1'
        if self.structure:
            self.assertNotEqual(os.environ.get('GITHUB_ACTIONS'),'true')
        self.child = subprocess.Popen(['unshare','--mount','--propagation','private',
            sys.executable,'-I','-B','-c',METER,str(self.root),'structure' if self.structure else 'live'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(self.reap)
        self.assertTrue(select.select([self.child.stdout],[],[],8)[0])
        ready = self.child.stdout.readline().strip()
        if not ready:
            self.child.wait(timeout=5)
            self.fail('foreign meter exited: '+self.child.stderr.read())
        self.assertEqual(ready,'foreign_meter_ready')
        self.foreign = os.readlink(f'/proc/{self.child.pid}/ns/mnt')
        self.assertNotEqual(self.local,self.foreign)
        self.assertFalse((self.root/'only-meter').exists())
        self.source = os.open(f'/proc/{self.child.pid}/root{self.root}/only-meter',mounts.DIR_FLAGS)
        self.addCleanup(os.close,self.source)
        self.pidfd = os.pidfd_open(self.child.pid)
        self.addCleanup(os.close,self.pidfd)

    def reap(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.communicate(timeout=5)

    def test_exact_foreign_mount_fd_and_live_peer_without_supervisor_setns(self):
        with self.assertRaises(OSError) as denied:
            mounts.readonly_view(self.source)
        self.assertEqual(denied.exception.errno,errno.EINVAL)
        view, identity = mounts.readonly_meter_view(self.source,self.pidfd,self.child.pid)
        try:
            self.assertEqual(os.readlink('/proc/self/ns/mnt'),self.local)
            self.assertFalse((self.root/'only-meter').exists())
            self.assertIsNone(mounts.check_view(self.source,view,identity))
            self.assertEqual(os.listdir(view),['vless-main'])
            self.assertEqual(os.fstat(view).st_ino,os.stat('..',dir_fd=view).st_ino)
            self.assertFalse(os.get_inheritable(view))
            with self.assertRaises(OSError) as readonly:
                os.unlink('vless-main',dir_fd=view)
            self.assertEqual(readonly.exception.errno,errno.EROFS)
            if not self.structure:
                expected = peers.capture_original(self.pidfd,self.child.pid)
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
                    conn.settimeout(2)
                    conn.connect(f'/proc/self/fd/{view}/vless-main')
                    self.assertIsNone(peers.verify_connected_peer(conn,expected))
                    conn.sendall(b'X')
                    self.assertEqual(conn.recv(1),b'Y')
            self.child.stdin.write('stop\n')
            self.child.stdin.flush()
            self.assertEqual(self.child.wait(timeout=5),0)
        finally:
            os.close(view)

    def test_wrong_pinned_pid_or_foreign_source_is_rejected(self):
        own = os.pidfd_open(os.getpid())
        local = os.open(self.root,mounts.DIR_FLAGS)
        try:
            with self.assertRaises(ValueError):
                mounts.readonly_meter_view(self.source,own,self.child.pid)
            with self.assertRaises(ValueError):
                mounts.readonly_meter_view(local,self.pidfd,self.child.pid)
            self.assertEqual(os.readlink('/proc/self/ns/mnt'),self.local)
        finally:
            os.close(own)
            os.close(local)
        self.child.kill()
        self.child.wait(timeout=5)
        with self.assertRaises(ValueError):
            mounts.readonly_meter_view(self.source,self.pidfd,self.child.pid)


if __name__ == '__main__':
    unittest.main()
