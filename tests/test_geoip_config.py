import unittest
from pathlib import Path

from app.config_loader import load_tasks
from app.cross_dedupe import RULE_FILE_PRIORITY


ROOT = Path(__file__).resolve().parents[1]


class GeoIPConfigTests(unittest.TestCase):
    def test_geoip_cn_fallback_precedes_final_match(self):
        lines = [
            line.strip()
            for line in (ROOT / "crl.ini").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith(";")
        ]
        geoip = "ruleset=🎯 全球直连,[]GEOIP,CN,no-resolve"
        final_match = "ruleset=🚀 节点选择,[]MATCH"
        self.assertIn(geoip, lines)
        self.assertIn(final_match, lines)
        self.assertLess(lines.index(geoip), lines.index(final_match))
        self.assertNotIn("ChinaIP.list", "\n".join(lines))

    def test_legacy_china_ip_task_and_artifact_are_removed(self):
        tasks = load_tasks(str(ROOT / "rule.json"))
        self.assertNotIn("ChinaIP.list", {task.output_file for task in tasks})
        self.assertNotIn("ChinaIP.list", RULE_FILE_PRIORITY)
        self.assertFalse((ROOT / "crl" / "ChinaIP.list").exists())

    def test_geo_database_is_configured_and_auto_updated(self):
        config = (ROOT / "default.yaml").read_text(encoding="utf-8")
        self.assertIn("geodata-mode: true", config)
        self.assertIn("geo-auto-update: true", config)
        self.assertIn("geo-update-interval: 24", config)
        self.assertIn("geoip:", config)


if __name__ == "__main__":
    unittest.main()
