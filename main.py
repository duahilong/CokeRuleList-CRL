import os
from typing import List

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

    output_path = write_rules_file(
        output_dir=OUTPUT_DIR,
        file_name=task.output_file,
        description=task.description,
        urls=task.urls,
        rules=sorted_rules,
        type_stats=type_stats,
    )

    print(f"已生成: {output_path}")
    print(f"   抓取成功/失败: {success_count}/{len(task.urls) - success_count}")
    print(f"   原始行数: {raw_rule_count}")
    print(f"   解析条数: {len(parsed_rules)}")
    print(f"   过滤条数: {filtered_count}")
    print(f"   输出条数: {len(sorted_rules)}")

    return BuildResult(
        output_file=task.output_file,
        description=task.description,
        source_count=len(task.urls),
        success_count=success_count,
        failed_count=len(task.urls) - success_count,
        raw_rule_count=raw_rule_count,
        parsed_rule_count=len(parsed_rules),
        final_rule_count=len(sorted_rules),
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

    generate_global_statistics(OUTPUT_DIR, results)
    return results


if __name__ == "__main__":
    run()
