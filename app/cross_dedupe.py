import os
from typing import Dict, List, Set

from .models import RuleTask
from .normalizer import normalize_filter_dedupe
from .parser import parse_content
from .sorter import sort_rules
from .writer import write_rules_file


# Higher priority first. Rules kept in earlier files will be removed from later files.
RULE_FILE_PRIORITY: List[str] = [
    "Coke.list",
    "YouTube.list",
    "Telegram.list",
    "GoogleFCM.list",
    "Google.list",
    "Ai.list",
    "GitHub.list",
    "Microsoft.list",
    "Steam.list",
    "Apple.list",
    "GameDownload.list",
    "ChinaMedia.list",
    "GlobalMedia.list",
    "Proxy.list",
    "Direct.list",
    "ChinaIP.list",
]


def _read_rule_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []

    rules: List[str] = []
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            text = line.strip()
            if text and not text.startswith("#"):
                rules.append(text)
    return rules


def _task_order(task_files: List[str]) -> List[str]:
    priority_set = set(RULE_FILE_PRIORITY)
    ordered = [name for name in RULE_FILE_PRIORITY if name in task_files and name != "Coke.list"]
    remaining = sorted(name for name in task_files if name not in priority_set)
    return ordered + remaining


def apply_priority_cross_file_dedupe(
    tasks: List[RuleTask],
    output_dir: str = "crl",
    manual_override_file: str = "Coke.list",
) -> Dict[str, int]:
    task_by_file: Dict[str, RuleTask] = {task.output_file: task for task in tasks}
    if not task_by_file:
        return {"total_dropped": 0, "files_touched": 0}

    ordered_files = _task_order(list(task_by_file.keys()))
    seen: Set[str] = set(_read_rule_lines(manual_override_file))
    dropped_total = 0
    files_touched = 0

    for file_name in ordered_files:
        task = task_by_file[file_name]
        output_path = os.path.join(output_dir, file_name)
        original_rules = _read_rule_lines(output_path)
        if not original_rules:
            continue

        kept_rules: List[str] = []
        for rule in original_rules:
            if rule in seen:
                continue
            seen.add(rule)
            kept_rules.append(rule)

        dropped = len(original_rules) - len(kept_rules)
        if dropped <= 0:
            continue

        dropped_total += dropped
        files_touched += 1

        parsed_items = []
        for line in kept_rules:
            items = parse_content(line, f"local://{file_name}")
            if items:
                parsed_items.append(items[0])

        normalized_items, type_stats, _ = normalize_filter_dedupe(parsed_items)
        sorted_items = sort_rules(normalized_items)

        write_rules_file(
            output_dir=output_dir,
            file_name=file_name,
            description=task.description,
            urls=task.urls,
            rules=sorted_items,
            type_stats=type_stats,
        )

        print(f"跨文件去重: {file_name} 删除 {dropped} 条重复规则")

    return {"total_dropped": dropped_total, "files_touched": files_touched}
