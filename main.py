import os
from typing import Dict, List, Tuple

from app.config_loader import load_tasks
from app.cross_dedupe import apply_priority_cross_file_dedupe
from app.fetcher import fetch_many
from app.models import BuildResult, RuleItem, RuleTask
from app.normalizer import normalize_filter_dedupe
from app.parser import parse_content
from app.sorter import sort_rules
from app.stats import generate_global_statistics
from app.writer import write_rules_file


CONFIG_FILE = "rule.json"
OUTPUT_DIR = "crl"


def _read_existing_output_stats(output_path: str) -> Tuple[int, Dict[str, int]]:
    if not os.path.exists(output_path):
        return 0, {}

    count = 0
    type_stats: Dict[str, int] = {}
    with open(output_path, "r", encoding="utf-8") as file:
        for line in file:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            count += 1
            rule_type = text.split(",", 1)[0].strip().upper()
            type_stats[rule_type] = type_stats.get(rule_type, 0) + 1
    return count, type_stats


def build_task(task: RuleTask) -> BuildResult:
    print(f"\n开始构建: {task.output_file}")
    print(f"   描述: {task.description}")
    print(f"   来源数量: {len(task.urls)}")

    fetch_results = fetch_many(task.urls, timeout=15, retries=2)

    parsed_rules: List[RuleItem] = []
    raw_rule_count = 0
    success_count = 0
    failed_urls: List[str] = []

    for result in fetch_results:
        if not result.success:
            failed_urls.append(result.url)
            print(f"   抓取失败: {result.url} ({result.error})")
            continue

        success_count += 1
        content_lines = result.content.splitlines()
        raw_rule_count += len(content_lines)
        rules = parse_content(result.content, result.url)
        parsed_rules.extend(rules)

    normalized_rules, type_stats, filtered_count = normalize_filter_dedupe(parsed_rules)
    sorted_rules = sort_rules(normalized_rules)

    output_path = os.path.join(OUTPUT_DIR, task.output_file)
    preserved_existing = False
    if success_count == 0 and os.path.exists(output_path):
        preserved_existing = True
        final_rule_count, existing_type_stats = _read_existing_output_stats(output_path)
        if existing_type_stats:
            type_stats = existing_type_stats
    else:
        output_path = write_rules_file(
            output_dir=OUTPUT_DIR,
            file_name=task.output_file,
            description=task.description,
            urls=task.urls,
            rules=sorted_rules,
            type_stats=type_stats,
        )
        final_rule_count = len(sorted_rules)

    print(f"已生成: {output_path}")
    print(f"   抓取成功/失败: {success_count}/{len(task.urls) - success_count}")
    print(f"   原始行数: {raw_rule_count}")
    print(f"   解析条数: {len(parsed_rules)}")
    print(f"   过滤条数: {filtered_count}")
    if preserved_existing:
        print("   写入策略: 全部来源失败，保留历史产物")
    print(f"   输出条数: {final_rule_count}")

    return BuildResult(
        output_file=task.output_file,
        description=task.description,
        source_count=len(task.urls),
        success_count=success_count,
        failed_count=len(task.urls) - success_count,
        raw_rule_count=raw_rule_count,
        parsed_rule_count=len(parsed_rules),
        final_rule_count=final_rule_count,
        type_stats=type_stats,
        urls=task.urls,
        failed_urls=failed_urls,
    )


def run() -> List[BuildResult]:
    if not os.path.exists(CONFIG_FILE):
        print(f"错误: 找不到配置文件 {CONFIG_FILE}")
        return []

    tasks = load_tasks(CONFIG_FILE)
    results: List[BuildResult] = []
    for task in tasks:
        results.append(build_task(task))

    dedupe_stats = apply_priority_cross_file_dedupe(
        tasks=tasks,
        output_dir=OUTPUT_DIR,
        manual_override_file="Coke.list",
    )
    if dedupe_stats["total_dropped"] > 0:
        print(
            f"\n跨文件去重完成: 处理文件 {dedupe_stats['files_touched']} 个, "
            f"删除重复规则 {dedupe_stats['total_dropped']} 条"
        )

    generate_global_statistics(
        OUTPUT_DIR,
        results,
        include_files=[task.output_file for task in tasks],
    )
    return results


if __name__ == "__main__":
    run()
