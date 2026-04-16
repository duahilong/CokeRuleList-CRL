import ipaddress
import re
from typing import List, Optional

from .models import RuleItem

_DOMAIN_TOKEN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{1,63}\.?$"
)


def _is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith(("#", ";", "//"))


def _infer_cidr_type(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
        return "IP-CIDR6" if network.version == 6 else "IP-CIDR"
    except ValueError:
        return "IP-CIDR6" if ":" in value else "IP-CIDR"


def _looks_like_domain(value: str) -> bool:
    text = value.strip().lower()
    if not text:
        return False
    if text.endswith("."):
        text = text[:-1]
    if "_" in text or " " in text or "/" in text or "," in text:
        return False
    return _DOMAIN_TOKEN_RE.match(text) is not None


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
            rule_type=_infer_cidr_type(text),
            value=text,
            options=[],
            source_url=source_url,
        )

    if _looks_like_domain(text):
        return RuleItem(
            raw=text,
            rule_type="DOMAIN-SUFFIX",
            value=text.lower().rstrip("."),
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
