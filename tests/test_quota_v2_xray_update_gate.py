"""The official Xray updater must not recover an old switch over a v2 ledger."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "deploy/xmesh-xray-update.py"
spec = importlib.util.spec_from_file_location("xray_update", SOURCE)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class XrayUpdateGateTest(unittest.TestCase):
    def test_quota_state_blocks_update_before_recovering_interrupted_switch(self):
        for name in ("genesis-quarantine-envelope.json", "genesis-positive-cap-u42.json",
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


if __name__ == "__main__":
    unittest.main()
