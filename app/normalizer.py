from typing import Dict, List, Set, Tuple

from .models import RuleItem


EXCLUDED_TYPES = {"IP-ASN"}


def normalize_rule(item: RuleItem) -> RuleItem:
    rule_type = item.rule_type.strip().upper()
    value = item.value.strip()
    options = [opt.strip() for opt in item.options if opt.strip()]

    if rule_type == "IP-CIDR" and value and "no-resolve" not in [opt.lower() for opt in options]:
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

        key = normalized_item.normalized
        if key in seen:
            continue

        seen.add(key)
        normalized.append(normalized_item)
        type_stats[normalized_item.rule_type] = type_stats.get(normalized_item.rule_type, 0) + 1

    return normalized, type_stats, filtered_count
