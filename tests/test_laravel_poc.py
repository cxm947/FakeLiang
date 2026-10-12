"""Offline checks for the pinned CVE-2021-3129 PoC script (no target involved)."""

import base64
import importlib.util
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from tests.support import ROOT
from skills import layout

POC = layout.skill_dir("exploit.laravel_ignition_rce", ROOT) / "poc" / "CVE-2021-3129.py"


def load_poc():
    spec = importlib.util.spec_from_file_location("agv_cve_2021_3129", POC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LaravelPocTests(unittest.TestCase):
    def setUp(self):
        self.poc = load_poc()

    def test_url_without_trailing_slash_is_pinned(self):
        self.assertEqual("/_ignition/execute-solution", self.poc.ENDPOINT)

    def test_quote_printable_round_trips_through_the_filter_chain(self):
        payload = bytes(range(256)) * 3
        encoded = self.poc.quote_printable(payload)
        self.assertTrue(encoded.startswith("A" * 100))
        # inverse of the step-4 chain: strip the "=00" separators, restore base64 padding
        base64_text = encoded[100:].replace("=00", "")
        restored = base64.b64decode(base64_text + "=" * (-len(base64_text) % 4))
        self.assertEqual(payload, restored)

    def test_missing_phpggc_is_a_setup_error_not_a_silent_failure(self):
        with self.assertRaises(SystemExit) as caught:
            self.poc.build_phar("id", phpggc="/nonexistent/phpggc", gadget="Monolog/RCE1",
                                workdir=str(ROOT))
        self.assertIn("phpggc not found", str(caught.exception))

    def test_cli_requires_url_and_command(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.poc.main([])


if __name__ == "__main__":
    unittest.main()
