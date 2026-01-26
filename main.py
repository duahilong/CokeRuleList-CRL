import requests
import json
import os
from datetime import datetime
from collections import defaultdict

def process_ip_rule(line):
    if line.startswith("IP-CIDR,"):
        parts = line.split(',')
        if len(parts) >= 2:
            ip_part = parts[1]
            if '/' in ip_part:
                return f"IP-CIDR,{ip_part},no-resolve"
    elif '/' in line and ',' not in line:
        parts = line.split('/')
        if len(parts) == 2:
            return f"IP-CIDR,{line},no-resolve"
    return None

def process_domain_rule(line):
    if line.startswith(("DOMAIN,", "DOMAIN-KEYWORD,", "DOMAIN-SUFFIX,", "URL-REGEX,")):
        return line
    return None

def check_duplicate_rules(output_dir="crl", config_file="rule.json", remove_duplicates=False):
    print("\n" + "="*60)
    print("开始检查文件间的重复规则...")
    print("="*60)
    
    if not os.path.exists(output_dir):
        print(f"错误: 找不到目录 {output_dir}")
        return
    
    if not os.path.exists(config_file):
        print(f"错误: 找不到配置文件 {config_file}")
        return
    
    # 读取配置文件，确定文件优先级（按配置文件中的顺序）
    with open(config_file, "r", encoding="utf-8") as f:
        task_config = json.load(f)
    
    # 获取所有 .list 文件，并按配置文件顺序排序
    list_files = [f for f in os.listdir(output_dir) if f.endswith('.list')]
    
    # 按配置文件中的顺序排序文件
    file_priority = {}
    priority = 0
    for file_name in task_config.keys():
        if file_name in list_files:
            file_priority[file_name] = priority
            priority += 1
    
    # 对于不在配置文件中的文件，优先级最低
    for file_name in list_files:
        if file_name not in file_priority:
            file_priority[file_name] = priority
            priority += 1
    
    sorted_files = sorted(list_files, key=lambda x: file_priority[x])
    
    if not sorted_files:
        print("没有找到 .list 文件")
        return
    
    print(f"文件优先级顺序：")
    for i, file_name in enumerate(sorted_files):
        print(f"  {i+1}. {file_name}")
    print()
    
    # 读取所有文件的规则
    file_rules = {}
    all_rules = defaultdict(list)
    
    for file_name in sorted_files:
        file_path = os.path.join(output_dir, file_name)
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        rules = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                rules.append(line)
                all_rules[line].append(file_name)
        
        file_rules[file_name] = rules
    
    # 找出重复的规则
    duplicate_rules = {rule: files for rule, files in all_rules.items() if len(files) > 1}
    
    if not duplicate_rules:
        print("✅ 没有发现文件间的重复规则！")
        print("="*60)
        return
    
    print(f"发现 {len(duplicate_rules)} 条重复规则：\n")
    
    # 按文件分组显示重复规则
    for rule, files in sorted(duplicate_rules.items()):
        print(f"规则: {rule}")
        print(f"  出现在文件: {', '.join(files)}")
        print()
    
    # 统计每个文件的重复规则数量
    print("="*60)
    print("各文件重复规则统计：")
    print("="*60)
    
    file_duplicate_stats = defaultdict(int)
    for rule, files in duplicate_rules.items():
        for file_name in files:
            file_duplicate_stats[file_name] += 1
    
    for file_name in sorted_files:
        total_rules = len(file_rules[file_name])
        duplicate_count = file_duplicate_stats[file_name]
        duplicate_percent = (duplicate_count / total_rules * 100) if total_rules > 0 else 0
        print(f"{file_name}: {duplicate_count}/{total_rules} 条重复 ({duplicate_percent:.2f}%)")
    
    print("="*60)
    
    # 如果需要去重
    if remove_duplicates:
        print("\n开始执行去重操作...")
        print("="*60)
        
        # 为每个规则确定保留的文件（优先级最高的）
        rule_keep_file = {}
        for rule, files in duplicate_rules.items():
            # 按优先级排序文件
            sorted_files_by_priority = sorted(files, key=lambda x: file_priority[x])
            # 保留优先级最高的文件中的规则
            keep_file = sorted_files_by_priority[0]
            rule_keep_file[rule] = keep_file
        
        # 统计每个文件需要删除的规则
        file_remove_stats = defaultdict(list)
        for rule, keep_file in rule_keep_file.items():
            for file_name in duplicate_rules[rule]:
                if file_name != keep_file:
                    file_remove_stats[file_name].append(rule)
        
        # 执行删除操作
        total_removed = 0
        for file_name in sorted_files:
            if file_name in file_remove_stats:
                rules_to_remove = set(file_remove_stats[file_name])
                original_count = len(file_rules[file_name])
                
                # 重新写入文件，排除需要删除的规则
                file_path = os.path.join(output_dir, file_name)
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
                
                # 更新文件头部的规则数量
                new_count = original_count - len(rules_to_remove)
                for i, line in enumerate(new_lines):
                    if line.startswith("# 条目:"):
                        new_lines[i] = f"# 条目: {new_count}\n"
                        break
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                
                print(f"✅ {file_name}: 删除 {len(rules_to_remove)} 条重复规则 ({original_count} -> {new_count})")
                total_removed += len(rules_to_remove)
        
        print("="*60)
        print(f"去重完成！共删除 {total_removed} 条重复规则")
        print("="*60)

def process_rules(file_name, urls, description=""):
    ip_rules = set()
    domain_rules = set()
    
    for url in urls:
        try:
            print(f"正在抓取: {url}")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith(('#', ';', '//', 'payload:')):
                        if line.startswith("- "):
                            line = line[2:]
                        
                        ip_rule = process_ip_rule(line)
                        if ip_rule:
                            ip_rules.add(ip_rule)
                        else:
                            domain_rule = process_domain_rule(line)
                            if domain_rule:
                                domain_rules.add(domain_rule)
                            else:
                                domain_rules.add(line)
        except Exception as e:
            print(f"抓取失败 {url}: {e}")
    
    output_dir = "crl"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_path = os.path.join(output_dir, file_name)
    rule_count = len(ip_rules) + len(domain_rules)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def rule_sort_key(rule):
        if rule.startswith("IP-CIDR,"):
            return (0, rule)
        elif rule.startswith("DOMAIN,"):
            return (1, rule)
        elif rule.startswith("DOMAIN-SUFFIX,"):
            return (2, rule)
        elif rule.startswith("DOMAIN-KEYWORD,"):
            return (3, rule)
        elif rule.startswith("URL-REGEX,"):
            return (4, rule)
        else:
            return (5, rule)
    
    all_rules = list(ip_rules) + list(domain_rules)
    all_rules.sort(key=rule_sort_key)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# 名称: {file_name}\n")
        f.write(f"# 描述: {description}\n")
        f.write(f"# 时间: {current_time}\n")
        f.write(f"# 条目: {rule_count}\n")
        f.write(f"# 引用:\n")
        for url in urls:
            f.write(f"#   {url}\n")
        f.write("\n")
        for rule in all_rules:
            f.write(rule + "\n")
    print(f"✅ 已生成: {output_path}")

if __name__ == "__main__":
    # 是否自动去重（True: 自动删除重复规则，False: 仅检查）
    AUTO_REMOVE_DUPLICATES = True
    
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
        
        # 3. 所有规则处理完成后，检查文件间的重复规则
        check_duplicate_rules(remove_duplicates=AUTO_REMOVE_DUPLICATES)