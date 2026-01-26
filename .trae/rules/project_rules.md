1.项目是用Python来实现。
2.项目处理规则集的逻辑是：
    1. 从项目的`rule.json`文件中读取规则集的URL。
    2. 下载规则集文件。
    3. 解析规则集文件，根据规则集的类型（如IP规则、域名规则等），将规则转换为项目的规则格式。
    4. 对转换后的规则进行去重和排序。
    5. 将转换后的规则保存到项目的规则文件中。
3.项目的规则文件格式是：
    1. 每个规则占一行。
    2. 规则的格式是：`规则类型,规则内容,规则参数`，例如：`DOMAIN-SUFFIX,example.com`,`DOMAIN,example.com`,`IP-CIDR,0.0.0.0/0,no-resolve`,`DOMAIN-KEYWORD,youtube`等。
    3. 每种规则类型使用间隔一行来隔离。
4.部分下载的规则集数据：
    1. [# Telegram
        #PROCESS-NAME,Telegram.exe
        #PROCESS-NAME,org.telegram.messenger
        DOMAIN-SUFFIX,t.me
        DOMAIN-SUFFIX,telegram.me
        DOMAIN-SUFFIX,telegram.org
        DOMAIN-SUFFIX,telesco.pe
        IP-CIDR,91.108.0.0/16,no-resolve
        IP-CIDR6,2001:b28:f23f::/48,no-resolve
        ]
    2. [# NAME: Direct
        # AUTHOR: blackmatrix7
        # REPO: https://github.com/blackmatrix7/ios_rule_script
        # UPDATED: 2025-08-12 02:08:14
        # DOMAIN: 56
        # DOMAIN-KEYWORD: 36
        # DOMAIN-SUFFIX: 139
        # PROCESS-NAME: 36
        # TOTAL: 267
        DOMAIN,ad.10010.com
        DOMAIN,ad.12306.cn
        DOMAIN-SUFFIX,52pt.site
        DOMAIN-SUFFIX,acg.rip
        DOMAIN-SUFFIX,anthelion.me
        ]