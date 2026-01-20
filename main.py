import requests
import json
import os
from datetime import datetime

def process_rules(file_name, urls, description=""):
    final_rules = set()
    for url in urls:
        try:
            print(f"正在抓取: {url}")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    # 过滤掉注释、空行、以及一些常见的说明文本
                    if line and not line.startswith(('#', ';', '//', 'payload:')):
                        # 如果是 Clash Provider 格式，去掉前面的 "- "
                        if line.startswith("- "):
                            line = line[2:]
                        final_rules.add(line)
        except Exception as e:
            print(f"抓取失败 {url}: {e}")
    
    output_dir = "crl"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_path = os.path.join(output_dir, file_name)
    rule_count = len(final_rules)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# 名称: {file_name}\n")
        f.write(f"# 描述: {description}\n")
        f.write(f"# 时间: {current_time}\n")
        f.write(f"# 条目: {rule_count}\n")
        f.write(f"# 引用:\n")
        for url in urls:
            f.write(f"#   {url}\n")
        f.write("\n")
        for rule in sorted(list(final_rules)):
            f.write(rule + "\n")
    print(f"✅ 已生成: {output_path}")

if __name__ == "__main__":
    # 1. 读取外部 JSON 配置文件
    config_file = "rule.json"
    
    if not os.path.exists(config_file):
        print(f"错误: 找不到配置文件 {config_file}")
    else:
        with open(config_file, "r", encoding="utf-8") as f:
            task_config = json.load(f)
        
        # 2. 遍历配置文件中的任务
        for output_file, config in task_config.items():
            urls = config.get("urls", [])
            description = config.get("description", "")
            process_rules(output_file, urls, description)