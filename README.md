# CokeRuleList-CRL

一个基于 `rule.json` 的 Clash 规则聚合与发布项目：

- 从多个公网规则源抓取规则内容
- 统一解析、标准化、去重和排序
- 输出到仓库内 `crl/` 目录供远程引用
- 通过 GitHub Actions 定时自动更新

## 项目特点

- **输入不变**：继续使用 `rule.json` 管理规则源
- **输出不变**：继续输出 `crl/*.list` 规则文件
- **处理升级**：内部重构为模块化流水线，便于维护与扩展
- **统计增强**：生成 `crl/tx.log`，包含总量、重复率与来源抓取情况

## 目录说明

- `rule.json`：规则任务配置（输出文件 + 描述 + 来源 URL）
- `main.py`：构建入口
- `app/`：核心处理模块（配置、抓取、解析、标准化、排序、写出、统计）
- `crl/`：生成后的规则文件与统计日志
- `.github/workflows/main.yml`：自动更新工作流
- `crl.ini`：订阅转换器规则模板示例

## 工作流程

1. 读取 `rule.json`
2. 拉取每个规则集配置中的来源 URL
3. 逐行解析规则（跳过空行和注释）
4. 标准化规则格式并去重
5. 按规则类型排序
6. 写入 `crl/*.list`
7. 生成 `crl/tx.log` 统计信息

## 本地使用

### 1) 安装依赖

```bash
pip install requests
```

### 2) 运行构建

```bash
python main.py
```

运行完成后可在 `crl/` 查看规则产物和统计日志。

## rule.json 格式

示例：

```json
{
  "Google.list": {
    "description": "Google服务规则集，包含Google服务",
    "urls": [
      "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.list"
    ]
  }
}
```

字段说明：

- `Google.list`：输出文件名（会写入 `crl/Google.list`）
- `description`：规则集描述（写入文件头）
- `urls`：来源地址列表（按顺序抓取并合并）

## 自动更新

工作流文件：`.github/workflows/main.yml`

- 支持定时触发（cron）
- 支持手动触发（workflow_dispatch）
- 构建后自动提交 `crl/*.list` 与 `crl/tx.log`

## 注意事项

- 上游规则源可能偶发超时，`tx.log` 会记录来源成功/失败情况
- 当前默认过滤 `IP-ASN` 规则类型
- Windows 终端显示中文乱码通常是编码问题，不影响文件内容
