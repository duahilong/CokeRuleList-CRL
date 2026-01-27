import requests
import json
import os
from datetime import datetime
from typing import Dict, List, Set


class Rule:
    def __init__(self, line: str):
        self.line = line.strip()
        self.type = self._extract_type()
    
    def _extract_type(self) -> str:
        if ',' in self.line:
            return self.line.split(',')[0].upper()
        elif '/' in self.line and ',' not in self.line:
            return 'IP-CIDR'
        else:
            return 'OTHER'
    
    def __str__(self):
        if self.type == 'IP-CIDR' and '/' in self.line and ',' not in self.line:
            return f"IP-CIDR,{self.line},no-resolve"
        return self.line
    
    def __hash__(self):
        return hash(str(self))
    
    def __eq__(self, other):
        if not isinstance(other, Rule):
            return False
        return str(self) == str(other)


class RuleProcessor:
    def __init__(self):
        self.rules: Set[Rule] = set()
        self.urls: List[str] = []
        self.stats: Dict[str, int] = {}
    
    def parse_line(self, line: str) -> Rule:
        line = line.strip()
        if not line or line.startswith(('#', ';', '//')):
            return None
        
        if line.startswith("- "):
            line = line[2:]
        
        return Rule(line)
    
    def fetch_rules(self, url: str) -> List[Rule]:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                rules = []
                for line in resp.text.splitlines():
                    rule = self.parse_line(line)
                    if rule:
                        rules.append(rule)
                return rules
            return []
        except Exception as e:
            print(f"抓取失败 {url}: {e}")
            return []
    
    def add_rules_from_url(self, url: str):
        self.urls.append(url)
        rules = self.fetch_rules(url)
        for rule in rules:
            self.rules.add(rule)
    
    def sort_rules(self) -> List[Rule]:
        priority_order = {
            'IP-CIDR': 0,
            'IP-CIDR6': 1,
            'DOMAIN': 2,
            'DOMAIN-SUFFIX': 3,
            'DOMAIN-KEYWORD': 4,
            'URL-REGEX': 5,
            'PROCESS-NAME': 6,
            'GEOIP': 7,
            'MATCH': 8,
            'RULE-SET': 9,
            'OTHER': 10,
        }
        
        return sorted(self.rules, key=lambda r: (priority_order.get(r.type, 99), str(r)))
    
    def update_stats(self):
        self.stats = {}
        for rule in self.rules:
            self.stats[rule.type] = self.stats.get(rule.type, 0) + 1


def process_rules(file_name: str, urls: List[str], description: str = ""):
    processor = RuleProcessor()
    
    for url in urls:
        print(f"正在抓取: {url}")
        processor.add_rules_from_url(url)
    
    processor.update_stats()
    
    output_dir = "crl"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_path = os.path.join(output_dir, file_name)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    sorted_rules = processor.sort_rules()
    
    filtered_rules = [rule for rule in sorted_rules if rule.type != 'IP-ASN']
    
    rule_count = len(filtered_rules)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# 名称: {file_name}\n")
        f.write(f"# 描述: {description}\n")
        f.write(f"# 时间: {current_time}\n")
        f.write(f"# 条目: {rule_count}\n")
        
        if processor.stats:
            f.write(f"# 规则统计: {json.dumps(processor.stats, ensure_ascii=False)}\n")
        
        f.write(f"# 引用:\n")
        for url in processor.urls:
            f.write(f"#   {url}\n")
        f.write("\n")
        
        last_type = None
        for rule in filtered_rules:
            if last_type is not None and rule.type != last_type:
                f.write("\n")
            f.write(str(rule) + "\n")
            last_type = rule.type
    
    print(f"✅ 已生成: {output_path}")
    print(f"   规则统计: {processor.stats}")


def generate_statistics():
    """
    生成统计信息，包括规则总数和重复规则数
    """
    output_dir = "crl"
    if not os.path.exists(output_dir):
        print("crl文件夹不存在")
        return
    
    all_rules = []
    file_rules = {}
    file_stats = {}
    
    for file_name in os.listdir(output_dir):
        if file_name.endswith('.list'):
            file_path = os.path.join(output_dir, file_name)
            rules = []
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        rules.append(line)
            
            file_rules[file_name] = rules
            all_rules.extend(rules)
    
    total_rules = len(all_rules)
    unique_rules = len(set(all_rules))
    duplicate_rules = total_rules - unique_rules
    
    for file_name in file_rules:
        current_file_rules = set(file_rules[file_name])
        other_files_rules = set()
        
        for other_file in file_rules:
            if other_file != file_name:
                other_files_rules.update(file_rules[other_file])
        
        duplicate_in_file = len(current_file_rules & other_files_rules)
        duplicate_count = duplicate_in_file
        
        file_stats[file_name] = {
            'total': len(file_rules[file_name]),
            'duplicate': duplicate_count,
            'duplicate_rate': (duplicate_count / len(file_rules[file_name]) * 100) if len(file_rules[file_name]) > 0 else 0
        }
    
    log_path = os.path.join(output_dir, "tx.log")
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"# 统计时间: {current_time}\n")
        f.write(f"# 规则总数: {total_rules}\n")
        f.write(f"# 唯一规则数: {unique_rules}\n")
        f.write(f"# 重复规则数: {duplicate_rules}\n")
        f.write(f"# 重复率: {(duplicate_rules/total_rules*100):.2f}%\n")
        f.write("\n# 各文件规则统计:\n")
        for file_name, stats in file_stats.items():
            f.write(f"#   {file_name}: {stats['total']} 条规则, 重复 {stats['duplicate']} 条, 重复率 {stats['duplicate_rate']:.2f}%\n")
    
    print(f"\n📊 统计信息已生成: {log_path}")
    print(f"   规则总数: {total_rules}")
    print(f"   唯一规则数: {unique_rules}")
    print(f"   重复规则数: {duplicate_rules}")
    print(f"   重复率: {(duplicate_rules/total_rules*100):.2f}%")


if __name__ == "__main__":
    CONFIG_FILE = "rule.json"
    
    if not os.path.exists(CONFIG_FILE):
        print(f"错误: 找不到配置文件 {CONFIG_FILE}")
    else:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            task_config = json.load(f)
        
        for output_file, config in task_config.items():
            urls = config.get("urls", [])
            description = config.get("description", "")
            process_rules(output_file, urls, description)
        
        generate_statistics()