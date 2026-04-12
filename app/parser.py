from typing import List, Optional

from .models import RuleItem


def _is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith(("#", ";", "//"))


def _parse_line(line: str, source_url: str) -> Optional[RuleItem]:
    if _is_comment_or_empty(line):
        return None

    text = line.strip()
    if text.startswith("- "):
        text = text[2:].strip()

    if not text:
        return None

    if "," in text:
        parts = [part.strip() for part in text.split(",")]
        rule_type = parts[0].upper()
        if len(parts) < 2 or not parts[1]:
            return None
        value = parts[1]
        options = [part for part in parts[2:] if part]
        return RuleItem(
            raw=text,
            rule_type=rule_type,
            value=value,
            options=options,
            source_url=source_url,
        )

    if "/" in text:
        return RuleItem(
            raw=text,
            rule_type="IP-CIDR",
            value=text,
            options=[],
            source_url=source_url,
        )

    return RuleItem(
        raw=text,
        rule_type="OTHER",
        value=text,
        options=[],
        source_url=source_url,
    )


def parse_content(content: str, source_url: str) -> List[RuleItem]:
    rules: List[RuleItem] = []
    for line in content.splitlines():
        item = _parse_line(line, source_url)
        if item is not None:
            rules.append(item)
    return rules
