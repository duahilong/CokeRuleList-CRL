import os
import tempfile
import unittest
from unittest.mock import patch

import main
from app.models import FetchResult, RuleTask


class BuildSafetyTests(unittest.TestCase):
    def _task(self):
        return RuleTask("Test.list", "safety test", ["https://example.com/rules.list"])

    def _write_history(self, output_dir, count):
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "Test.list"), "w", encoding="utf-8") as file:
            file.write("# historical rules\n")
            for index in range(count):
                file.write(f"DOMAIN-SUFFIX,old-{index}.example\n")

    def _fetch(self, content):
        return FetchResult(url="https://example.com/rules.list", success=True, content=content)

    def test_sharp_shrink_preserves_existing_output(self):
        with tempfile.TemporaryDirectory(dir="tests", prefix="_tmp_safety_") as temp_dir:
            self._write_history(temp_dir, 100)
            content = "\n".join(f"DOMAIN-SUFFIX,new-{i}.example" for i in range(10))
            with patch.object(main, "OUTPUT_DIR", temp_dir), patch.object(main, "fetch_many", return_value=[self._fetch(content)]):
                result = main.build_task(self._task())
            self.assertEqual(100, result.final_rule_count)
            with open(os.path.join(temp_dir, "Test.list"), encoding="utf-8") as file:
                self.assertIn("old-0.example", file.read())

    def test_normal_shrink_replaces_existing_output(self):
        with tempfile.TemporaryDirectory(dir="tests", prefix="_tmp_safety_") as temp_dir:
            self._write_history(temp_dir, 100)
            content = "\n".join(f"DOMAIN-SUFFIX,new-{i}.example" for i in range(60))
            with patch.object(main, "OUTPUT_DIR", temp_dir), patch.object(main, "fetch_many", return_value=[self._fetch(content)]):
                result = main.build_task(self._task())
            self.assertEqual(60, result.final_rule_count)
            with open(os.path.join(temp_dir, "Test.list"), encoding="utf-8") as file:
                self.assertIn("new-0.example", file.read())


if __name__ == "__main__":
    unittest.main()
