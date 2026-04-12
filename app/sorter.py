from typing import List

from .models import RuleItem


PRIORITY_ORDER = {
    "IP-CIDR": 0,
    "IP-CIDR6": 1,
    "DOMAIN": 2,
    "DOMAIN-SUFFIX": 3,
    "DOMAIN-KEYWORD": 4,
    "URL-REGEX": 5,
    "PROCESS-NAME": 6,
    "GEOIP": 7,
    "MATCH": 8,
    "RULE-SET": 9,
    "OTHER": 10,
}


def sort_rules(items: List[RuleItem]) -> List[RuleItem]:
    return sorted(
        items,
        key=lambda item: (PRIORITY_ORDER.get(item.rule_type, 99), item.normalized),
    )
