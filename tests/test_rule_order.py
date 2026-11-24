import re
import unittest
from pathlib import Path

from app.cross_dedupe import RULE_FILE_PRIORITY


ROOT = Path(__file__).resolve().parents[1]


class RuleOrderTests(unittest.TestCase):
    def test_subscription_and_cross_file_dedupe_share_order(self):
        config = (ROOT / "crl.ini").read_text(encoding="utf-8")
        active_config = "\n".join(
            line for line in config.splitlines() if not line.strip().startswith(";")
        )
        subscription_files = re.findall(r"/crl/([^/]+\.list)", active_config)
        dedupe_files = [
            name for name in RULE_FILE_PRIORITY
            if name not in {"Coke.list", "Apple.list", "Steam.list"}
        ]
        self.assertEqual(dedupe_files, subscription_files)

    def test_specific_files_precede_broad_collections(self):
        config = (ROOT / "crl.ini").read_text(encoding="utf-8")
        positions = {
            name: config.index(f"/crl/{name}")
            for name in (
                "GoogleFCM.list", "GitHub.list", "GameDownload.list",
                "Ai.list", "GlobalMedia.list", "Proxy.list", "Direct.list",
            )
        }
        for specific in ("GoogleFCM.list", "GitHub.list", "GameDownload.list", "Ai.list"):
            self.assertLess(positions[specific], positions["GlobalMedia.list"])
            self.assertLess(positions[specific], positions["Proxy.list"])
        self.assertLess(positions["GlobalMedia.list"], positions["Direct.list"])
        self.assertLess(positions["Proxy.list"], positions["Direct.list"])


if __name__ == "__main__":
    unittest.main()
