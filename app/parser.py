import ipaddress
import re
from typing import List, Optional

from .models import RuleItem

_DOMAIN_TOKEN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{1,63}\.?$"
)
_DOMAIN_LABEL_RE = re.compile(r"^(?=.{1,63}$)(?!-)[A-Za-z0-9-]+(?<!-)$")


def _is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith(("#", ";", "//"))


def _cidr_item(value: str, source_url: str, raw: str) -> Optional[RuleItem]:
    text = value.strip()
    if "/" not in text:
        return None

    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None

    rule_type = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
    return RuleItem(
        raw=raw,
        rule_type=rule_type,
        value=str(network),
        options=[],
        source_url=source_url,
    )


def _strip_inline_comment(text: str) -> str:
    cut_index = len(text)
    for marker in (" #", " ;", " //"):
        marker_index = text.find(marker)
        if marker_index != -1 and marker_index < cut_index:
            cut_index = marker_index
    return text[:cut_index].strip()


def _looks_like_domain(value: str) -> bool:
    text = value.strip().lower()
    if not text:
        return False
    if text.endswith("."):
        text = text[:-1]
    if "_" in text or " " in text or "/" in text or "," in text:
        return False
    if _DOMAIN_TOKEN_RE.match(text) is not None:
        return True

    if _DOMAIN_LABEL_RE.match(text) is None:
        return False

    if "-" in text and not text.startswith("xn--"):
        return False

    # Accept single-label suffix tokens such as "cn" / "xn--fiqs8s"
    # while avoiding plain numeric strings.
    return any(ch.isalpha() for ch in text)


def _parse_line(line: str, source_url: str) -> Optional[RuleItem]:
    if _is_comment_or_empty(line):
        return None

    text = line.strip()
    if text.startswith("- "):
        text = text[2:].strip()
    text = _strip_inline_comment(text)

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

    cidr = _cidr_item(text, source_url, text)
    if cidr is not None:
        return cidr

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
