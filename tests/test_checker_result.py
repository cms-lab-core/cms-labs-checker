import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "checker_result.py"
SPEC = importlib.util.spec_from_file_location("checker_result", SCRIPT)
protocol = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(protocol)


class CheckerResultTests(unittest.TestCase):
    def payload(self, size=5000):
        return json.dumps({
            "max_score": 12, "current_score": 8, "result_display": "8/12",
            "report": "Диагностика " * size, "tasks": [{"title": "FDB", "complete": False}],
        }, ensure_ascii=False).encode()

    def test_large_result_and_diagnostics(self):
        payload = self.payload()
        frame = protocol.encode_result(payload)
        self.assertGreater(len(payload), 4096)
        self.assertEqual(protocol.decode_result(b"before\n" + frame + b"after\n"), json.loads(payload))
        self.assertTrue(all(len(line.split(b" ", 2)[2]) <= 2048 for line in frame.splitlines()))

    def test_missing_duplicated_and_reordered_chunks(self):
        lines = protocol.encode_result(self.payload()).splitlines(keepends=True)
        for frame in (b"".join(lines[1:]), b"".join(lines[:1] + lines[2:]),
                      b"".join(lines + lines[:1]), b"".join(reversed(lines))):
            with self.subTest(frame_size=len(frame)), self.assertRaises(ValueError):
                protocol.decode_result(frame)

    def test_old_json_and_unknown_version_are_rejected(self):
        for logs in (self.payload(1), b"CMS_LABS_CHECKER_RESULT_V2 nope\n", b"fatal SSH error\n"):
            with self.subTest(logs=logs), self.assertRaises(ValueError):
                protocol.decode_result(logs)

    def test_limits_and_invalid_score(self):
        with self.assertRaises(ValueError):
            protocol.encode_result(b"x" * (protocol.MAX_RESULT_BYTES + 1))
        with self.assertRaises(ValueError):
            protocol.decode_result(b"x" * (protocol.MAX_LOG_BYTES + 1))
        for payload in (b'{"max_score":1,"current_score":2,"result_display":"bad"}',
                        b'{"max_score":NaN,"current_score":0,"result_display":"bad"}', b"[]"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                protocol.encode_result(payload)

    def test_cli_and_failure_emit_no_partial_json(self):
        encoded = subprocess.run([sys.executable, str(SCRIPT), "encode"],
                                 input=self.payload(), capture_output=True, check=True)
        decoded = subprocess.run([sys.executable, str(SCRIPT), "decode"],
                                 input=encoded.stdout, capture_output=True, check=True)
        self.assertEqual(json.loads(decoded.stdout), json.loads(self.payload()))
        failed = subprocess.run([sys.executable, str(SCRIPT), "decode"],
                                input=b"checker crashed\n", capture_output=True)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout, b"")
        self.assertIn(b"result missing", failed.stderr)


if __name__ == "__main__":
    unittest.main()
