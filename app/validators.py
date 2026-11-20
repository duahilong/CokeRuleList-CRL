import ipaddress
import re
from typing import Optional

from .models import RuleItem


SUPPORTED_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "PROCESS-NAME",
    "URL-REGEX",
    "MATCH",
    "RULE-SET",
}

_DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SINGLE_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _valid_domain(value: str, allow_single_label: bool = False) -> bool:
    if not value or len(value) > 253 or value != value.strip():
        return False
    if _DOMAIN_RE.fullmatch(value):
        return True
    return allow_single_label and _SINGLE_LABEL_RE.fullmatch(value) is not None


def validate_rule(item: RuleItem) -> Optional[str]:
    """Return a rejection reason, or None when the normalized rule is valid."""
    rule_type = item.rule_type
    value = item.value

    if rule_type not in SUPPORTED_RULE_TYPES:
        return f"unsupported rule type: {rule_type}"
    if not value and rule_type != "MATCH":
        return "missing rule value"
    if rule_type in {"IP-ASN", "OTHER"}:
        return f"excluded rule type: {rule_type}"

    if rule_type == "DOMAIN":
        return None if _valid_domain(value) else "invalid DOMAIN value"
    if rule_type == "DOMAIN-SUFFIX":
        return None if _valid_domain(value, allow_single_label=True) else "invalid DOMAIN-SUFFIX value"
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return "invalid IP network"
        expected_version = 6 if rule_type == "IP-CIDR6" else 4
        return None if network.version == expected_version else "IP version mismatch"
    if rule_type == "GEOIP":
        return None if re.fullmatch(r"[A-Za-z]{2}", value) else "invalid GEOIP value"
    if rule_type in {"PROCESS-NAME", "DOMAIN-KEYWORD"}:
        return None if value == value.strip() else "value has surrounding whitespace"
    if rule_type in {"MATCH", "RULE-SET", "URL-REGEX"}:
        return None

    return f"unsupported rule type: {rule_type}"
