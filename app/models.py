from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RuleTask:
    output_file: str
    description: str
    urls: List[str]


@dataclass
class RuleItem:
    raw: str
    rule_type: str
    value: str
    options: List[str] = field(default_factory=list)
    source_url: str = ""

    @property
    def normalized(self) -> str:
        if self.options:
            return ",".join([self.rule_type, self.value] + self.options)
        return ",".join([self.rule_type, self.value])


@dataclass
class FetchResult:
    url: str
    success: bool
    status_code: Optional[int] = None
    content: str = ""
    error: Optional[str] = None


@dataclass
class BuildResult:
    output_file: str
    description: str
    source_count: int
    success_count: int
    failed_count: int
    raw_rule_count: int
    parsed_rule_count: int
    final_rule_count: int
    type_stats: Dict[str, int]
    urls: List[str]
    failed_urls: List[str]
