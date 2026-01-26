import requests
import json
import os
import re
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
from enum import Enum


class RuleType(Enum):
    IP_CIDR = "IP-CIDR"
    IP_CIDR6 = "IP-CIDR6"
    DOMAIN = "DOMAIN"
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    DOMAIN_KEYWORD = "DOMAIN-KEYWORD"
    URL_REGEX = "URL-REGEX"
    PROCESS_NAME = "PROCESS-NAME"
    GEOIP = "GEOIP"
    MATCH = "MATCH"
    RULE_SET = "RULE-SET"
    OTHER = "OTHER"


class Rule:
    def __init__(self, rule_type: RuleType, value: str, params: Dict[str, str] = None):
        self.type = rule_type
        self.value = value
        self.params = params or {}
    
    def __str__(self):
        if self.params:
            params_str = "," + ",".join([f"{k}={v}" if v else k for k, v in self.params.items()])
        else:
            params_str = ""
        return f"{self.type.value},{self.value}{params_str}"
    
    def __hash__(self):
        return hash(str(self))
    
    def __eq__(self, other):
        if not isinstance(other, Rule):
            return False
        return str(self) == str(other)
    
    def __lt__(self, other):
        return str(self) < str(other)


class RuleParser:
    @staticmethod
    def parse_line(line: str) -> Optional[Rule]:
        line = line.strip()
        if not line or line.startswith(('#', ';', '//')):
            return None
        
        if line.startswith("- "):
            line = line[2:]
        
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 2:
            return None
        
        rule_type_str = parts[0].upper()
        value = parts[1]
        params = {}
        
        if len(parts) > 2:
            for param in parts[2:]:
                if '=' in param:
                    key, val = param.split('=', 1)
                    params[key.strip()] = val.strip()
                else:
                    params[param.strip()] = ""
        
        try:
            rule_type = RuleType(rule_type_str)
            return Rule(rule_type, value, params)
        except ValueError:
            return Rule(RuleType.OTHER, value, params)
    
    @staticmethod
    def parse_simple_ip(line: str) -> Optional[Rule]:
        line = line.strip()
        if not line or line.startswith(('#', ';', '//')):
            return None
        
        if '/' in line and ',' not in line:
            parts = line.split('/')
            if len(parts) == 2:
                return Rule(RuleType.IP_CIDR, line, {"no-resolve": ""})
        
        return None
    
    @staticmethod
    def parse_from_text(text: str) -> List[Rule]:
        rules = []
        for line in text.splitlines():
            rule = RuleParser.parse_line(line)
            if rule:
                rules.append(rule)
            else:
                simple_ip = RuleParser.parse_simple_ip(line)
                if simple_ip:
                    rules.append(simple_ip)
        return rules
    
    @staticmethod
    def parse_from_url(url: str, timeout: int = 15) -> List[Rule]:
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                return RuleParser.parse_from_text(resp.text)
            return []
        except Exception as e:
            print(f"抓取失败 {url}: {e}")
            return []


class RuleProcessor:
    def __init__(self):
        self.ip_rules: Set[Rule] = set()
        self.domain_rules: Set[Rule] = set()
        self.other_rules: Set[Rule] = set()
        self.urls: List[str] = []
    
    def add_rule(self, rule: Rule):
        if rule.type in [RuleType.IP_CIDR, RuleType.IP_CIDR6]:
            self.ip_rules.add(rule)
        elif rule.type in [RuleType.DOMAIN, RuleType.DOMAIN_SUFFIX, 
                       RuleType.DOMAIN_KEYWORD, RuleType.URL_REGEX,
                       RuleType.PROCESS_NAME, RuleType.GEOIP]:
            self.domain_rules.add(rule)
        else:
            self.other_rules.add(rule)
    
    def add_rules(self, rules: List[Rule]):
        for rule in rules:
            self.add_rule(rule)
    
    def add_rules_from_url(self, url: str):
        self.urls.append(url)
        rules = RuleParser.parse_from_url(url)
        self.add_rules(rules)
    
    def get_all_rules(self) -> List[Rule]:
        return list(self.ip_rules) + list(self.domain_rules) + list(self.other_rules)
    
    def get_rule_count(self) -> int:
        return len(self.ip_rules) + len(self.domain_rules) + len(self.other_rules)
    
    def get_statistics(self) -> Dict[str, int]:
        stats = defaultdict(int)
        for rule in self.ip_rules:
            stats[rule.type.value] += 1
        for rule in self.domain_rules:
            stats[rule.type.value] += 1
        for rule in self.other_rules:
            stats[rule.type.value] += 1
        return dict(stats)
    
    def sort_rules(self) -> List[Rule]:
        def rule_sort_key(rule: Rule) -> Tuple[int, str]:
            priority_order = {
                RuleType.IP_CIDR: 0,
                RuleType.IP_CIDR6: 1,
                RuleType.DOMAIN: 2,
                RuleType.DOMAIN_SUFFIX: 3,
                RuleType.DOMAIN_KEYWORD: 4,
                RuleType.URL_REGEX: 5,
                RuleType.PROCESS_NAME: 6,
                RuleType.GEOIP: 7,
                RuleType.MATCH: 8,
                RuleType.RULE_SET: 9,
                RuleType.OTHER: 10,
            }
            return (priority_order.get(rule.type, 99), str(rule))
        
        return sorted(self.get_all_rules(), key=rule_sort_key)


class DuplicateChecker:
    def __init__(self, output_dir: str = "crl", config_file: str = "rule.json"):
        self.output_dir = output_dir
        self.config_file = config_file
        self.file_priority: Dict[str, int] = {}
        self.file_rules: Dict[str, List[Rule]] = {}
        self.all_rules: Dict[str, List[str]] = defaultdict(list)
    
    def load_config(self) -> Dict:
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"找不到配置文件 {self.config_file}")
        
        with open(self.config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    
    def load_file_priority(self, task_config: Dict):
        list_files = [f for f in os.listdir(self.output_dir) if f.endswith('.list')]
        
        priority = 0
        for file_name in task_config.keys():
            if file_name in list_files:
                self.file_priority[file_name] = priority
                priority += 1
        
        for file_name in list_files:
            if file_name not in self.file_priority:
                self.file_priority[file_name] = priority
                priority += 1
        
        return sorted(list_files, key=lambda x: self.file_priority[x])
    
    def load_all_rules(self, sorted_files: List[str]):
        for file_name in sorted_files:
            file_path = os.path.join(self.output_dir, file_name)
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            rules = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    rules.append(line)
                    self.all_rules[line].append(file_name)
            
            self.file_rules[file_name] = rules
    
    def find_duplicates(self) -> Dict[str, List[str]]:
        return {rule: files for rule, files in self.all_rules.items() if len(files) > 1}
    
    def check(self, remove_duplicates: bool = False):
        print("\n" + "=" * 60)
        print("开始检查文件间的重复规则...")
        print("=" * 60)
        
        if not os.path.exists(self.output_dir):
            print(f"错误: 找不到目录 {self.output_dir}")
            return
        
        try:
            task_config = self.load_config()
        except FileNotFoundError as e:
            print(f"错误: {e}")
            return
        
        sorted_files = self.load_file_priority(task_config)
        
        if not sorted_files:
            print("没有找到 .list 文件")
            return
        
        print(f"文件优先级顺序：")
        for i, file_name in enumerate(sorted_files):
            print(f"  {i+1}. {file_name}")
        print()
        
        self.load_all_rules(sorted_files)
        duplicate_rules = self.find_duplicates()
        
        if not duplicate_rules:
            print("✅ 没有发现文件间的重复规则！")
            print("=" * 60)
            return
        
        print(f"发现 {len(duplicate_rules)} 条重复规则：\n")
        
        for rule, files in sorted(duplicate_rules.items()):
            print(f"规则: {rule}")
            print(f"  出现在文件: {', '.join(files)}")
            print()
        
        print("=" * 60)
        print("各文件重复规则统计：")
        print("=" * 60)
        
        file_duplicate_stats = defaultdict(int)
        for rule, files in duplicate_rules.items():
            for file_name in files:
                file_duplicate_stats[file_name] += 1
        
        for file_name in sorted_files:
            total_rules = len(self.file_rules[file_name])
            duplicate_count = file_duplicate_stats[file_name]
            duplicate_percent = (duplicate_count / total_rules * 100) if total_rules > 0 else 0
            print(f"{file_name}: {duplicate_count}/{total_rules} 条重复 ({duplicate_percent:.2f}%)")
        
        print("=" * 60)
        
        if remove_duplicates:
            self.remove_duplicates(duplicate_rules, sorted_files)
    
    def remove_duplicates(self, duplicate_rules: Dict[str, List[str]], sorted_files: List[str]):
        print("\n开始执行去重操作...")
        print("=" * 60)
        
        rule_keep_file = {}
        for rule, files in duplicate_rules.items():
            sorted_files_by_priority = sorted(files, key=lambda x: self.file_priority[x])
            keep_file = sorted_files_by_priority[0]
            rule_keep_file[rule] = keep_file
        
        file_remove_stats = defaultdict(list)
        for rule, keep_file in rule_keep_file.items():
            for file_name in duplicate_rules[rule]:
                if file_name != keep_file:
                    file_remove_stats[file_name].append(rule)
        
        total_removed = 0
        for file_name in sorted_files:
            if file_name in file_remove_stats:
                rules_to_remove = set(file_remove_stats[file_name])
                original_count = len(self.file_rules[file_name])
                
                file_path = os.path.join(self.output_dir, file_name)
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                new_lines = []
                for line in lines:
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith('#'):
                        if stripped_line not in rules_to_remove:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                
                new_count = original_count - len(rules_to_remove)
                for i, line in enumerate(new_lines):
                    if line.startswith("# 条目:"):
                        new_lines[i] = f"# 条目: {new_count}\n"
                        break
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                
                print(f"✅ {file_name}: 删除 {len(rules_to_remove)} 条重复规则 ({original_count} -> {new_count})")
                total_removed += len(rules_to_remove)
        
        print("=" * 60)
        print(f"去重完成！共删除 {total_removed} 条重复规则")
        print("=" * 60)


class RuleGenerator:
    def __init__(self, output_dir: str = "crl"):
        self.output_dir = output_dir
        self.processor = RuleProcessor()
    
    def process_urls(self, urls: List[str]):
        for url in urls:
            print(f"正在抓取: {url}")
            self.processor.add_rules_from_url(url)
    
    def generate_file(self, file_name: str, description: str = ""):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        output_path = os.path.join(self.output_dir, file_name)
        rule_count = self.processor.get_rule_count()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        sorted_rules = self.processor.sort_rules()
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# 名称: {file_name}\n")
            f.write(f"# 描述: {description}\n")
            f.write(f"# 时间: {current_time}\n")
            f.write(f"# 条目: {rule_count}\n")
            
            stats = self.processor.get_statistics()
            if stats:
                f.write(f"# 规则统计: {json.dumps(stats, ensure_ascii=False)}\n")
            
            f.write(f"# 引用:\n")
            for url in self.processor.urls:
                f.write(f"#   {url}\n")
            f.write("\n")
            
            for rule in sorted_rules:
                f.write(str(rule) + "\n")
        
        print(f"✅ 已生成: {output_path}")
        print(f"   规则统计: {stats}")


def process_rules(file_name: str, urls: List[str], description: str = ""):
    generator = RuleGenerator()
    generator.process_urls(urls)
    generator.generate_file(file_name, description)


if __name__ == "__main__":
    AUTO_REMOVE_DUPLICATES = True
    OUTPUT_DIR = "crl"
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
        
        checker = DuplicateChecker(OUTPUT_DIR, CONFIG_FILE)
        checker.check(remove_duplicates=AUTO_REMOVE_DUPLICATES)