import unittest

from app.models import RuleItem
from app.normalizer import normalize_filter_dedupe
from app.parser import parse_content


class ParserNormalizerTests(unittest.TestCase):
    def _normalized_rules(self, text: str):
        items = parse_content(text, "local://unit-test")
        normalized, _, filtered = normalize_filter_dedupe(items)
        return items, normalized, filtered

    def test_invalid_slash_line_is_filtered(self):
        items, normalized, filtered = self._normalized_rules("foo/bar")
        self.assertEqual(1, len(items))
        self.assertEqual("OTHER", items[0].rule_type)
        self.assertEqual([], normalized)
        self.assertEqual(1, filtered)

    def test_inline_comment_is_stripped_for_csv_rule(self):
        _, normalized, filtered = self._normalized_rules("DOMAIN-SUFFIX,example.com # trailing")
        self.assertEqual(["DOMAIN-SUFFIX,example.com"], [item.normalized for item in normalized])
        self.assertEqual(0, filtered)

    def test_inline_comment_is_stripped_for_bare_domain(self):
        _, normalized, filtered = self._normalized_rules("example.com # trailing")
        self.assertEqual(["DOMAIN-SUFFIX,example.com"], [item.normalized for item in normalized])
        self.assertEqual(0, filtered)

    def test_single_label_suffix_kept_but_random_hyphen_label_filtered(self):
        _, normalized, filtered = self._normalized_rules("cn")
        self.assertEqual(["DOMAIN-SUFFIX,cn"], [item.normalized for item in normalized])
        self.assertEqual(0, filtered)

        items, normalized, filtered = self._normalized_rules("INVALID-LINE-WITHOUT-COMMA")
        self.assertEqual(1, len(items))
        self.assertEqual("OTHER", items[0].rule_type)
        self.assertEqual([], normalized)
        self.assertEqual(1, filtered)

    def test_cidr_is_validated_and_canonicalized(self):
        _, normalized, filtered = self._normalized_rules("1.2.3.4/24 # trailing")
        self.assertEqual(["IP-CIDR,1.2.3.0/24,no-resolve"], [item.normalized for item in normalized])
        self.assertEqual(0, filtered)

    def test_invalid_typed_cidr_is_filtered(self):
        items = [
            RuleItem(
                raw="IP-CIDR,foo/bar",
                rule_type="IP-CIDR",
                value="foo/bar",
                options=[],
                source_url="local://unit-test",
            )
        ]
        normalized, _, filtered = normalize_filter_dedupe(items)
        self.assertEqual([], normalized)
        self.assertEqual(1, filtered)


if __name__ == "__main__":
    unittest.main()
