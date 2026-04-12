import json
import os
from datetime import datetime
from typing import Dict, List

from .models import RuleItem


def ensure_output_dir(path: str) -> None:
    if not os.path.exists(path):
        os.makedirs(path)


def write_rules_file(
    output_dir: str,
    file_name: str,
    description: str,
    urls: List[str],
    rules: List[RuleItem],
    type_stats: Dict[str, int],
) -> str:
    ensure_output_dir(output_dir)

    output_path = os.path.join(output_dir, file_name)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(f"# 名称: {file_name}\n")
        file.write(f"# 描述: {description}\n")
        file.write(f"# 时间: {current_time}\n")
        file.write(f"# 条目: {len(rules)}\n")
        file.write(f"# 规则统计: {json.dumps(type_stats, ensure_ascii=False)}\n")
        file.write("# 引用:\n")
        for url in urls:
            file.write(f"#   {url}\n")
        file.write("\n")

        last_type = None
        for item in rules:
            if last_type is not None and item.rule_type != last_type:
                file.write("\n")
            file.write(item.normalized + "\n")
            last_type = item.rule_type

    return output_path
