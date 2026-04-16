import ipaddress
from typing import Dict, List, Set, Tuple

from .models import RuleItem


EXCLUDED_TYPES = {"IP-ASN", "OTHER"}


def _normalize_cidr_rule_type(rule_type: str, value: str) -> str:
    if rule_type not in {"IP-CIDR", "IP-CIDR6"} or "/" not in value:
        return rule_type

    try:
        network = ipaddress.ip_network(value, strict=False)
        return "IP-CIDR6" if network.version == 6 else "IP-CIDR"
    except ValueError:
        return "IP-CIDR6" if ":" in value else rule_type


def _parse_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def normalize_rule(item: RuleItem) -> RuleItem:
    rule_type = item.rule_type.strip().upper()
    value = item.value.strip()
    options = [opt.strip() for opt in item.options if opt.strip()]
    rule_type = _normalize_cidr_rule_type(rule_type, value)

    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        network = _parse_network(value)
        if network is not None:
            value = str(network)

    lower_options = {opt.lower() for opt in options}

    if rule_type in {"IP-CIDR", "IP-CIDR6"} and value and "no-resolve" not in lower_options:
        options.append("no-resolve")

    return RuleItem(
        raw=item.raw,
        rule_type=rule_type,
        value=value,
        options=options,
        source_url=item.source_url,
    )


def normalize_filter_dedupe(items: List[RuleItem]) -> Tuple[List[RuleItem], Dict[str, int], int]:
    normalized: List[RuleItem] = []
    type_stats: Dict[str, int] = {}
    seen: Set[str] = set()
    filtered_count = 0

    for item in items:
        normalized_item = normalize_rule(item)
        if normalized_item.rule_type in EXCLUDED_TYPES:
            filtered_count += 1
            continue

        if normalized_item.rule_type in {"IP-CIDR", "IP-CIDR6"} and _parse_network(normalized_item.value) is None:
            filtered_count += 1
            continue

        key = normalized_item.normalized
        if key in seen:
            continue

        seen.add(key)
        normalized.append(normalized_item)
        type_stats[normalized_item.rule_type] = type_stats.get(normalized_item.rule_type, 0) + 1

    return normalized, type_stats, filtered_count
