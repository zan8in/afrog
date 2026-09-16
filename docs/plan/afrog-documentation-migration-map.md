# afrog 文档迁移清单

## 1. 说明

本清单用于指导 `afrog` 现有文档向新文档结构迁移，目标是：

- 为每一份旧文档明确归宿。
- 区分“保留、拆分、合并、归档、跳转”几类处理方式。
- 给迁移工作排定优先级，避免同时改动过多入口。

新文档结构以 `docs/zh/` 为主，英文版按同路径镜像创建 `docs/en/`。

## 2. 处理动作定义

- `保留`：内容基本稳定，仅换路径或格式。
- `拆分`：一篇旧文档拆成多篇新文档。
- `合并`：多篇旧文档合并成一篇新文档。
- `归档`：保留历史内容，但不再作为权威入口。
- `跳转`：旧入口保留说明，跳转到新文档。

## 3. 新文档目标结构

```text
docs/zh/
  index.md
  getting-started/
  user-guide/
  poc/
  sdk/
  reference/
  tutorials/
  faq/
  contributing/
  release-notes/
```

## 4. 迁移总表

| 现有路径 | 目标路径 | 处理方式 | 优先级 | 备注 |
| --- | --- | --- | --- | --- |
| `README.md` | 根首页入口 | 拆分 | P0 | 精简为项目简介、安装、常用命令、Docs 入口 |
| `docs/README_CN.md` | `docs/zh/index.md` + `getting-started/*` + `user-guide/*` + `reference/cli-options.md` | 拆分 | P0 | 当前中文入口内容过重，需拆开 |
| `docs/afrog-poc-guide.md` | `docs/zh/poc/quickstart.md` + `docs/zh/poc/syntax.md` + `docs/zh/poc/rules-and-expression.md` + `docs/zh/poc/extractors.md` + `docs/zh/poc/best-practices.md` | 拆分 | P0 | PoC 主文档，优先重构 |
| `docs/afrog-helper-function.md` | `docs/zh/poc/helper-functions.md` | 保留/整理 | P0 | 作为参考手册保留 |
| `docs/requires-gating-guide.md` | `docs/zh/poc/requires.md` | 保留/整理 | P1 | 主题明确，适合单篇迁移 |
| `docs/SDK使用指南_中文.md` | `docs/zh/sdk/overview.md` + `docs/zh/sdk/quickstart.md` + `docs/zh/sdk/sync-and-async.md` + `docs/zh/sdk/handlers-and-streams.md` + `docs/zh/sdk/config-reference.md` + `docs/zh/sdk/api-reference.md` + `docs/zh/sdk/examples.md` + `docs/zh/sdk/faq.md` | 拆分 | P0 | 体量大，但结构天然适合拆分 |
| `docs/SDK_Usage_Guide_English.md` | `docs/en/sdk/*` | 拆分 | P2 | 先按中文路径建英文镜像 |
| `docs/TCP/tcp-ssl-multi-step-session.md` | `docs/zh/poc/tcp.md` | 合并 | P1 | 并入 TCP/SSL 章节 |
| `docs/tutorial/rumen-dao-rutu/00-outline.md` | `docs/zh/tutorials/index.md` 或归档 | 归档 | P3 | 仅保留为系列说明 |
| `docs/tutorial/rumen-dao-rutu/01-getting-started.md` | `docs/zh/tutorials/first-web-scan.md` | 保留/整理 | P2 | 归为教程，不做权威参考 |
| `docs/tutorial/rumen-dao-rutu/02-cli-usage.md` | `docs/zh/tutorials/cli-workflow.md` + `docs/zh/reference/cli-options.md` | 拆分 | P1 | 参数定义与示例分离 |
| `docs/tutorial/rumen-dao-rutu/03-configuration.md` | `docs/zh/tutorials/configuration-basics.md` + `docs/zh/user-guide/configuration.md` | 拆分 | P1 | 教程与参考分离 |
| `docs/tutorial/rumen-dao-rutu/03-configuration copy.md` | 无 | 归档/删除候选 | P3 | 明显重复，待确认后清理 |
| `docs/tutorial/rumen-dao-rutu/04-poc-basics.md` | `docs/zh/tutorials/first-poc.md` + `docs/zh/poc/quickstart.md` | 拆分 | P1 | 保留教程属性 |
| `docs/tutorial/rumen-dao-rutu/05-poc-advanced.md` | `docs/zh/tutorials/requires-chain.md` + `docs/zh/poc/requires.md` + `docs/zh/poc/brute.md` + `docs/zh/poc/oob.md` | 拆分 | P1 | 高级技巧拆到权威章节 |
| `docs/tutorial/rumen-dao-rutu/06-contribution.md` | `docs/zh/contributing/poc-contribution.md` | 保留/整理 | P2 | 迁到贡献指南 |
| `docs/tutorial/rumen-dao-rutu/07-resume.md` | `docs/zh/tutorials/large-scale-resume.md` + `docs/zh/user-guide/resume.md` | 拆分 | P1 | 一篇教程，一篇操作说明 |
| `docs/tutorial/series-params-to-principles/00-outline.md` | `docs/zh/tutorials/advanced/index.md` 或归档 | 归档 | P3 | 系列规划稿，不作主入口 |
| `docs/tutorial/series-params-to-principles/01-target-input.md` | `docs/zh/tutorials/target-input-principles.md` + `docs/zh/user-guide/targets.md` | 拆分 | P2 | 原理说明与操作说明分离 |
| `docs/tutorial/series-params-to-principles/02-task-smart-timeout.md` | `docs/zh/tutorials/smart-timeout.md` + `docs/zh/user-guide/performance.md` | 拆分 | P2 | 场景说明并入性能章节 |
| `afrog.wiki/Home.md` | `docs/zh/index.md` | 跳转 | P2 | Wiki 首页改为跳转页 |
| `afrog.wiki/Getting-Started.md` | `docs/zh/getting-started/install.md` + `docs/zh/getting-started/first-scan.md` | 跳转 | P2 | 历史页面保留说明 |
| `afrog.wiki/Configuration.md` | `docs/zh/user-guide/configuration.md` | 跳转 | P2 | 迁移后不再单独维护 |
| `afrog.wiki/Usage.md` | `docs/zh/user-guide/*` + `docs/zh/reference/cli-options.md` | 拆分/跳转 | P2 | 使用说明重构后再替换 |
| `afrog.wiki/Examples.md` | `docs/zh/getting-started/quick-examples.md` + `docs/zh/tutorials/*` | 拆分/跳转 | P2 | 示例与教程统一管理 |
| `afrog.wiki/FAQ.md` | `docs/zh/faq/common-issues.md` | 合并/跳转 | P2 | FAQ 独立化 |
| `afrog.wiki/Afrog-PoC-规则编写权威指南.md` | `docs/zh/poc/*` | 拆分/跳转 | P1 | 与 `docs/afrog-poc-guide.md` 同步整合 |
| `afrog.wiki/Afrog-PoC-内置函数.md` | `docs/zh/poc/helper-functions.md` | 跳转 | P1 | 保留历史入口，正文迁走 |
| `afrog.wiki/requires 指纹门控：用法教程与问题答疑.md` | `docs/zh/poc/requires.md` | 跳转 | P1 | 作为专项说明迁入 |
| `afrog.wiki/内置便捷变量与 Helper 速查.md` | `docs/zh/reference/built-in-variables.md` + `docs/zh/poc/helper-functions.md` | 拆分 | P2 | 变量与函数分层 |
| `afrog.wiki/OOB 体系大升级：新版写法与证据教程（v3.3.9）.md` | `docs/zh/poc/oob.md` + `docs/zh/release-notes/*` | 拆分 | P2 | “教程”与“版本说明”拆开 |
| `afrog.wiki/Afrog 指纹 PoC 编写保姆级教程：从 0 到 1 实战.md` | `docs/zh/tutorials/fingerprint-poc.md` + `docs/zh/poc/quickstart.md` | 拆分 | P3 | 作为场景教程保留 |
| `afrog.wiki/Afrog 指纹 PoC 进阶教程：巧用“机会主义”模式 (Opportunistic).md` | `docs/zh/tutorials/opportunistic-mode.md` + `docs/zh/poc/requires.md` | 拆分 | P3 | 机制说明进入权威页 |
| `afrog.wiki/Afrog 支持星球PoC自动更新功能.md` | `docs/zh/user-guide/poc-source.md` 或 `docs/zh/tutorials/poc-update.md` | 待定 | P3 | 视是否仍为产品主功能决定归类 |

## 5. 首批交付清单（P0）

建议第一批先落以下内容：

1. `docs/plan/afrog-documentation-prd.md`
2. `docs/plan/afrog-documentation-migration-map.md`
3. `docs/zh/index.md`
4. `docs/zh/getting-started/install.md`
5. `docs/zh/getting-started/first-scan.md`
6. `docs/zh/reference/cli-options.md`
7. `docs/zh/user-guide/configuration.md`
8. `docs/zh/user-guide/output-and-report.md`
9. `docs/zh/poc/quickstart.md`
10. `docs/zh/poc/syntax.md`
11. `docs/zh/poc/helper-functions.md`
12. `docs/zh/sdk/quickstart.md`

## 6. 迁移顺序建议

### 步骤 1：先立新目录

- 建立 `docs/zh/` 和 `docs/en/` 结构。
- 为首批核心页面创建占位文件。

### 步骤 2：迁核心入口

- 改造 `README.md` 和中文首页。
- 建立新文档首页和导航关系。

### 步骤 3：迁 PoC 与 SDK 核心手册

- 优先拆 `afrog-poc-guide.md`。
- 再拆 `SDK使用指南_中文.md`。

### 步骤 4：迁教程与 FAQ

- 将教程移入 `tutorials/`。
- FAQ 合并为统一入口。

### 步骤 5：处理 Wiki

- 在 Wiki 核心入口加入迁移说明。
- 逐步将正文转为跳转或历史归档。

## 7. 待确认事项

以下内容建议在实施前确认：

1. `afrog-website` 是直接读取主仓库 Markdown，还是通过同步脚本复制。
2. 是否需要在第一期就引入全文搜索。
3. `release-notes/` 是否要按版本拆页。
4. `星球 PoC 自动更新` 是否作为正式产品功能保留在主文档中。
5. 是否保留部分 Wiki 教程作为“社区文章”区分展示。

## 8. 后续建议

基于本迁移清单，下一步适合继续产出：

1. 首批 10 篇文档的章节提纲
2. 首页信息架构与导航草图
3. 文档 frontmatter 模板
4. 英文占位页策略与 CI 校验规则
