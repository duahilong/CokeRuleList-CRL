# 变更说明

## 2026-11-24：规则顺序重构与 QuixoticHeart 来源接入

### 1. 调整订阅匹配顺序

按照“具体服务优先，宽泛集合靠后”的原则重排 `crl.ini`：

1. `Coke-Direct.list` 手工例外
2. `GoogleFCM.list`、`GitHub.list`、`GameDownload.list`、`ChinaMedia.list` 具体服务
3. `Ai.list`、`YouTube.list`、`Google.list`、`Telegram.list`、`Microsoft.list`
4. `GlobalMedia.list`、`Proxy.list` 宽泛集合
5. `Direct.list` 大型直连集合
6. `GEOIP,CN,no-resolve` 中国 IP 兜底
7. `MATCH` 最终兜底

同步调整 `app/cross_dedupe.py` 中的 `RULE_FILE_PRIORITY`，确保跨文件去重后的规则归属与订阅实际命中顺序一致。`Apple.list` 和 `Steam.list` 当前未被订阅引用，因此放在去重末尾，不再从活动规则集中抢占规则。

主要行为变化：

- `android.apis.google.com` 优先归属 GoogleFCM。
- `github-cloud.s3.amazonaws.com` 优先归属 GitHub。
- `origin-a.akamaihd.net`、`assets1.xboxlive.com` 等下载域名优先归属 GameDownload，避免被 Proxy 或 Microsoft 的宽泛规则提前截获。
- 中国媒体的具体域名规则先于 GlobalMedia、Proxy 和 Direct。

### 2. 接入 QuixoticHeart 规则来源

在 `rule.json` 中新增以下来源，继续经过现有解析、标准化、合法性校验和跨文件去重流程：

| 目标任务 | 新增来源 | 构建结果 |
|---|---|---|
| `Ai.list` | `QuixoticHeart/rule-set/meta/ai.list` | 66 → 297 条，补充 Claude、Anthropic、Copilot、Perplexity 等 AI 服务 |
| `GameDownload.list` | `QuixoticHeart/rule-set/meta/games-cn.list` | 55 → 145 条，补充网易、暴雪等国内游戏下载 CDN |
| `GoogleFCM.list` | `QuixoticHeart/rule-set/meta/googlefcm.list` | 41 → 41 条，与现有 blackmatrix7 来源完全重合，无独立新增 |

新增来源均为 Surge 文本格式，与现有解析器兼容，无需新增格式适配器。GoogleFCM 的 QuixoticHeart 来源属于冗余来源，后续可以移除以减少抓取。

### 3. 文档与测试

- README 新增规则匹配顺序及去重归属说明。
- 新增 `tests/test_rule_order.py`，检查订阅与去重顺序一致，以及具体服务先于宽泛集合。
- 全部 20 项单元测试通过。
- 真实上游抓取与构建成功，跨文件移除 916 条完全重复规则。
- 本次构建生成 125,588 条唯一规则；相比接入前新增 222 条，其中包含少量原有上游的自然更新。

### 4. 文件范围

主要配置：`crl.ini`、`rule.json`、`app/cross_dedupe.py`  
生成产物：`crl/*.list`、`crl/tx.log`  
测试与文档：`tests/test_rule_order.py`、`README.md`、`CHANGELOG.md`
