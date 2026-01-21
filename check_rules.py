import re

def analyze_rules(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    rules = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            rules.append(line)
    
    print(f"总规则数: {len(rules)}")
    
    # 按类型分类
    domain_rules = []
    keyword_rules = []
    suffix_rules = []
    ipcidr_rules = []
    ipcidr6_rules = []
    process_rules = []
    
    for rule in rules:
        if rule.startswith('DOMAIN,'):
            domain_rules.append(rule)
        elif rule.startswith('DOMAIN-KEYWORD,'):
            keyword_rules.append(rule)
        elif rule.startswith('DOMAIN-SUFFIX,'):
            suffix_rules.append(rule)
        elif rule.startswith('IP-CIDR,'):
            ipcidr_rules.append(rule)
        elif rule.startswith('IP-CIDR6,'):
            ipcidr6_rules.append(rule)
        elif rule.startswith('PROCESS-NAME,'):
            process_rules.append(rule)
    
    print(f"\n规则类型统计:")
    print(f"  DOMAIN: {len(domain_rules)}")
    print(f"  DOMAIN-KEYWORD: {len(keyword_rules)}")
    print(f"  DOMAIN-SUFFIX: {len(suffix_rules)}")
    print(f"  IP-CIDR: {len(ipcidr_rules)}")
    print(f"  IP-CIDR6: {len(ipcidr6_rules)}")
    print(f"  PROCESS-NAME: {len(process_rules)}")
    
    # 检查完全重复
    print(f"\n检查完全重复的规则...")
    unique_rules = set(rules)
    if len(rules) == len(unique_rules):
        print("  ✓ 没有完全重复的规则")
    else:
        print(f"  ✗ 发现 {len(rules) - len(unique_rules)} 个重复规则")
    
    # 检查语义重复
    print(f"\n检查语义重复的规则...")
    
    # 提取域名
    domain_names = set()
    for rule in domain_rules:
        name = rule.split(',', 1)[1].strip()
        domain_names.add(name)
    
    # 检查 DOMAIN-SUFFIX 和 DOMAIN 的冲突
    print(f"\n  检查 DOMAIN-SUFFIX 和 DOMAIN 的冲突...")
    conflicts = []
    for suffix_rule in suffix_rules:
        suffix = suffix_rule.split(',', 1)[1].strip()
        for domain in domain_names:
            if domain == suffix or domain.endswith('.' + suffix):
                conflicts.append((suffix_rule, f"DOMAIN,{domain}"))
    
    if conflicts:
        print(f"    ✗ 发现 {len(conflicts)} 个冲突:")
        for i, (suffix, domain) in enumerate(conflicts[:10], 1):
            print(f"      {i}. {suffix} 覆盖 {domain}")
        if len(conflicts) > 10:
            print(f"      ... 还有 {len(conflicts) - 10} 个冲突")
    else:
        print(f"    ✓ 没有发现冲突")
    
    # 检查 DOMAIN-SUFFIX 和 DOMAIN-SUFFIX 的包含关系
    print(f"\n  检查 DOMAIN-SUFFIX 的包含关系...")
    suffix_names = [rule.split(',', 1)[1].strip() for rule in suffix_rules]
    suffix_names_sorted = sorted(suffix_names, key=lambda x: len(x), reverse=True)
    
    contains = []
    for i, longer in enumerate(suffix_names_sorted):
        for shorter in suffix_names_sorted[i+1:]:
            if longer.endswith('.' + shorter):
                contains.append((longer, shorter))
    
    if contains:
        print(f"    ✗ 发现 {len(contains)} 个包含关系:")
        for i, (longer, shorter) in enumerate(contains[:10], 1):
            print(f"      {i}. DOMAIN-SUFFIX,{shorter} 覆盖 DOMAIN-SUFFIX,{longer}")
        if len(contains) > 10:
            print(f"      ... 还有 {len(contains) - 10} 个包含关系")
    else:
        print(f"    ✓ 没有发现包含关系")
    
    # 检查 DOMAIN-KEYWORD 和 DOMAIN-SUFFIX 的冲突
    print(f"\n  检查 DOMAIN-KEYWORD 和 DOMAIN-SUFFIX 的冲突...")
    keyword_suffix_conflicts = []
    for keyword_rule in keyword_rules:
        keyword = keyword_rule.split(',', 1)[1].strip()
        for suffix in suffix_names:
            if keyword in suffix or suffix in keyword:
                keyword_suffix_conflicts.append((keyword_rule, f"DOMAIN-SUFFIX,{suffix}"))
    
    if keyword_suffix_conflicts:
        print(f"    ✗ 发现 {len(keyword_suffix_conflicts)} 个潜在冲突:")
        for i, (keyword, suffix) in enumerate(keyword_suffix_conflicts[:10], 1):
            print(f"      {i}. {keyword} 和 {suffix}")
        if len(keyword_suffix_conflicts) > 10:
            print(f"      ... 还有 {len(keyword_suffix_conflicts) - 10} 个冲突")
    else:
        print(f"    ✓ 没有发现冲突")
    
    # 检查 IP-CIDR 的重复
    print(f"\n  检查 IP-CIDR 的重复...")
    ipcidr_names = [rule.split(',', 1)[1].strip() for rule in ipcidr_rules]
    ipcidr_unique = set(ipcidr_names)
    if len(ipcidr_names) == len(ipcidr_unique):
        print(f"    ✓ 没有重复的 IP-CIDR")
    else:
        print(f"    ✗ 发现 {len(ipcidr_names) - len(ipcidr_unique)} 个重复的 IP-CIDR")
    
    # 检查 PROCESS-NAME 的重复
    print(f"\n  检查 PROCESS-NAME 的重复...")
    process_names = [rule.split(',', 1)[1].strip() for rule in process_rules]
    process_unique = set(process_names)
    if len(process_names) == len(process_unique):
        print(f"    ✓ 没有重复的 PROCESS-NAME")
    else:
        print(f"    ✗ 发现 {len(process_names) - len(process_unique)} 个重复的 PROCESS-NAME")
        duplicates = [name for name in process_names if process_names.count(name) > 1]
        for dup in set(duplicates):
            print(f"      - {dup}")

if __name__ == "__main__":
    analyze_rules("crl/Direct.list")