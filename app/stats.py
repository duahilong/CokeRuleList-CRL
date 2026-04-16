import os
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from .models import BuildResult


def _read_rules_from_file(file_path: str) -> List[str]:
    rules: List[str] = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            text = line.strip()
            if text and not text.startswith("#"):
                rules.append(text)
    return rules


def generate_global_statistics(
    output_dir: str = "crl",
    build_results: Optional[List[BuildResult]] = None,
    include_files: Optional[Sequence[str]] = None,
) -> None:
    if not os.path.exists(output_dir):
        print("crl文件夹不存在")
        return

    file_rules: Dict[str, List[str]] = {}
    all_rules: List[str] = []

    candidate_files = sorted(file_name for file_name in os.listdir(output_dir) if file_name.endswith(".list"))
    if include_files is not None:
        include_set = set(include_files)
        candidate_files = [file_name for file_name in candidate_files if file_name in include_set]

    for file_name in candidate_files:
        file_path = os.path.join(output_dir, file_name)
        rules = _read_rules_from_file(file_path)
        file_rules[file_name] = rules
        all_rules.extend(rules)

    total_rules = len(all_rules)
    unique_rules = len(set(all_rules))
    duplicate_rules = total_rules - unique_rules
    duplicate_rate = (duplicate_rules / total_rules * 100) if total_rules else 0.0

    file_stats: Dict[str, Dict[str, float]] = {}
    for file_name, rules in file_rules.items():
        current_set = set(rules)
        other_set = set()
        for other_name, other_rules in file_rules.items():
            if other_name != file_name:
                other_set.update(other_rules)

        overlap = len(current_set & other_set)
        total = len(rules)
        file_stats[file_name] = {
            "total": total,
            "duplicate": overlap,
            "duplicate_rate": (overlap / total * 100) if total else 0.0,
        }

    log_path = os.path.join(output_dir, "tx.log")
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_path, "w", encoding="utf-8") as file:
        file.write(f"# 统计时间: {current_time}\n")
        file.write(f"# 规则总数: {total_rules}\n")
        file.write(f"# 唯一规则数: {unique_rules}\n")
        file.write(f"# 重复规则数: {duplicate_rules}\n")
        file.write(f"# 重复率: {duplicate_rate:.2f}%\n")

        if build_results:
            file.write("\n# 本次构建抓取统计:\n")
            for result in build_results:
                file.write(
                    "#   "
                    f"{result.output_file}: 来源 {result.source_count} 个, "
                    f"成功 {result.success_count} 个, 失败 {result.failed_count} 个\n"
                )
                if result.failed_urls:
                    for failed_url in result.failed_urls:
                        file.write(f"#     失败来源: {failed_url}\n")

        file.write("\n# 各文件规则统计:\n")

        for file_name, stats in file_stats.items():
            file.write(
                "#   "
                f"{file_name}: {int(stats['total'])} 条规则, "
                f"重复 {int(stats['duplicate'])} 条, "
                f"重复率 {stats['duplicate_rate']:.2f}%\n"
            )

    print(f"\n统计信息已生成: {log_path}")
    print(f"   规则总数: {total_rules}")
    print(f"   唯一规则数: {unique_rules}")
    print(f"   重复规则数: {duplicate_rules}")
    print(f"   重复率: {duplicate_rate:.2f}%")
