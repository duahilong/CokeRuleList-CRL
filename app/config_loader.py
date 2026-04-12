import json
from typing import List

from .models import RuleTask


def load_tasks(config_file: str) -> List[RuleTask]:
    with open(config_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("配置文件根节点必须是 JSON 对象")

    tasks: List[RuleTask] = []
    for output_file, config in data.items():
        if not isinstance(config, dict):
            raise ValueError(f"任务配置格式错误: {output_file}")

        urls = config.get("urls", [])
        description = config.get("description", "")

        if not isinstance(urls, list) or not all(isinstance(url, str) for url in urls):
            raise ValueError(f"urls 字段格式错误: {output_file}")

        tasks.append(
            RuleTask(
                output_file=output_file,
                description=description if isinstance(description, str) else "",
                urls=urls,
            )
        )

    return tasks
