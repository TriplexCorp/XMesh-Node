"""The official Xray updater must not recover an old switch over a v2 ledger."""
import importlib.util
import json
import subprocess
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "deploy/xmesh-xray-update.py"
spec = importlib.util.spec_from_file_location("xray_update", SOURCE)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class XrayUpdateGateTest(unittest.TestCase):
    def test_quota_state_blocks_update_before_recovering_interrupted_switch(self):
        for name in ("quota-revocation-deny-pending",
                     "genesis-quarantine-envelope.json",
                     "genesis-reservation-prepared-u42.json",
                     "genesis-reservation-confirmed-u42.json",
                     "genesis-positive-cap-u42.json",
                     "calendar-successor-u42-test.json",
                     "calendar-fence-u42-test.json", "calendar-meter-u42-test.json",
                     "calendar-delivery-u42-test.json", "calendar-positive-u42-test.json",
                     "wal-cap-u42-test.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                # Unreadable or missing target is not evidence it is safe to restart.
                (state / name).symlink_to("missing")
                prior = state / "updates/1"
                prior.mkdir(parents=True)
                journal = prior / "transaction.json"
                record = json.dumps({"version": "26.10.31", "phase": "switching"})
                journal.write_text(record)
                events = []
                operation = updater.Updater(state=state, docker=("unavailable-docker",),
                                            emit=events.append)
                result = operation.perform("26.10.31", 2)
                self.assertEqual(events, [result])
                self.assertFalse(result["success"])
                self.assertEqual(result["rollback"], "unchanged")
                self.assertIn("Quota V2 runtime state present", result["detail"])
                self.assertEqual(operation.counter, 0)
                self.assertEqual(journal.read_text(), record)
                self.assertFalse((state / "updates/2/transaction.json").exists())


class ColdBootstrapLedgerGateTest(unittest.TestCase):
    def test_cold_bootstrap_and_operational_reinstall_refuse_every_quota_phase(self):
        # Execute the real shell guard, using only a disposable replacement
        # for its absolute state root. No apt, Docker or systemd is invoked.
        source_root = Path(__file__).resolve().parents[1]
        protected = (
            "genesis-quarantine-envelope.json",
            "genesis-reservation-prepared-u42.json",
            "genesis-reservation-confirmed-u42.json",
            "genesis-positive-cap-u42.json",
            "calendar-successor-u42-reservation.json",
            "calendar-fence-u42-reservation.json",
            "calendar-meter-u42-reservation.json",
            "calendar-delivery-u42-reservation.json",
            "calendar-positive-u42-reservation.json",
            "wal-cap-u42-runtime.json",
        )
        for source, terminator in (
            (source_root / "bootstrap.sh", "\ndone"),
            (source_root / "deploy/install-v6-strict-operational-agents.sh",
             "\n  done"),
        ):
            raw = source.read_text()
            start = raw.index("for quota_evidence in /var/lib/xmesh-xray-sync/")
            end = raw.index(terminator, start) + len(terminator)
            guard = raw[start:end]
            with tempfile.TemporaryDirectory(prefix="quota-v2-bootstrap-") as tmp:
                command = "set -Eeuo pipefail\n" + guard.replace(
                    "/var/lib/xmesh-xray-sync", tmp)
                def check():
                    return subprocess.run(
                        ["bash", "-ec", command], capture_output=True,
                        text=True, timeout=5)
                self.assertEqual(check().returncode, 0)
                for marker in protected:
                    with self.subTest(source=source.name, marker=marker):
                        item = Path(tmp) / marker
                        # A dangling symlink is still an unsafe marker:
                        # an updater must not treat it as clean state.
                        item.symlink_to("missing")
                        try:
                            result = check()
                            self.assertEqual(result.returncode, 2)
                            self.assertIn("Quota V2", result.stderr)
                        finally:
                            item.unlink()
                self.assertEqual(check().returncode, 0)


if __name__ == "__main__":
    unittest.main()
