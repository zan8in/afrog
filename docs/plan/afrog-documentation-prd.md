# afrog 文档重构 PRD

## 1. 背景

重构前，`afrog` 的文档入口分散在 `README`、`docs/`、`afrog.wiki` 和官网仓库中，存在以下问题：

- 缺少唯一权威入口，用户不清楚该优先阅读哪一份文档。
- 内容按时间自然堆积，未按用户角色和使用场景分层。
- 教程、参考、机制说明、FAQ 混放，检索成本高。
- 中文和英文没有统一的结构策略，后续双语维护成本高。
- 单个入口页堆叠大量链接，用户不知道该先看哪一篇。

本 PRD 记录本次信息架构重构的目标、结构和验收标准。重构已在 `afrog` 主仓库落地；`afrog-website` 的同步将在主仓库内容完善后单独进行。

## 2. 目标

### 2.1 产品目标

建立一套可长期维护的文档体系，使其具备如下特征：

- 入口唯一：`README` 是唯一主入口，且只分发到四本手册。
- 结构清晰：用户可以快速定位所需信息。
- 内容按角色分层，兼顾使用者、PoC 作者和 SDK 用户。
- 中文优先落地，英文在同一结构下平滑补齐。
- 文档可持续维护，并能跟随代码演进稳定更新。

### 2.2 成功标准

- 新用户 5 分钟内完成第一次扫描。
- PoC 作者 15 分钟内写出第一条可运行 PoC。
- SDK 用户 20 分钟内完成最小集成。
- 从 `README` 出发，任意一本手册最多 3 次点击可达。
- 中文与英文目录结构完全一致。

## 3. 非目标

- 一次性重写所有历史文章。
- 在第一版就补齐全量英文正文。
- 在 Wiki 中继续扩展新的权威说明文档。
- 在本阶段同步改动 `afrog-website`。

## 4. 目标用户

### 4.1 使用者

关注安装、首次扫描、参数、配置、输出、性能和排障。

### 4.2 PoC 作者

关注 PoC 结构、表达式、提取器、内置函数、`requires`、`brute`、OOB、调试和最佳实践。

### 4.3 开发者 / 集成方

关注 SDK、同步异步执行、回调与流、输出结构、配置项和内存控制。

### 4.4 Curated 用户

关注 curated PoC 的授权、挂载、更新与在引擎中的启用方式。

## 5. 核心原则

1. `README` 是唯一主入口。
2. `afrog` 主仓库是文档内容真源。
3. `README` 只承担产品门面与四本手册入口，不承载完整手册。
4. 每本手册内部只有一层目录（手册首页），逐层深入。
5. 手册正文页不做链接墙，只保留必要的行内引用。
6. 中文优先，但必须从一开始就保持英文镜像结构。
7. `afrog-website` 只负责渲染，不承载独立正文。

## 6. 载体职责划分

### 6.1 `afrog` 主仓库

- 维护文档正文。
- 与代码变更一起评审文档改动。
- 作为官网文档的数据真源。

### 6.2 `afrog-website`

- 负责站点渲染、导航、搜索、国际化切换和 SEO。
- 现阶段暂不改动；待主仓库内容完善后再同步目录与新增页面。

### 6.3 `README.md` 与 `docs/README_CN.md`

- 项目介绍、安装方式、三个最高频命令示例、四本手册入口。
- 中英文两份 README 必须保持完全相同的章节结构，语言切换互指。

### 6.4 `afrog.wiki`

- 仅保留历史文章归档。
- 迁移完成后，在旧页面顶部增加“已迁移到 Docs”的说明或跳转。

## 7. 信息架构

`README`（唯一主入口）下挂四本手册：

| 手册 | 目录 | 首页 |
| --- | --- | --- |
| 使用指南 / User Guide | `docs/{zh,en}/user-guide/` | `01-overview.md` |
| PoC 编写指南 / PoC Authoring Guide | `docs/{zh,en}/poc/` | `01-quickstart.md` |
| SDK 使用指南 / SDK Usage Guide | `docs/{zh,en}/sdk/` | `01-quickstart.md` |
| Curated PoC / Curated PoC | `docs/{zh,en}/curated/` | `01-overview.md` |

文档源目录：

```text
docs/
  zh/
    index.md
    user-guide/
      01-overview.md
      02-install.md
      03-first-scan.md
      04-cli-options.md
      05-configuration.md
      06-output-and-report.md
      07-tips.md
    poc/
      01-quickstart.md
      02-syntax.md
      03-helper-functions.md
      04-requires.md
      05-brute.md
      06-oob.md
      07-raw-http.md
      08-tcp.md
      09-contributors.md
    sdk/
      01-quickstart.md
      02-sync-and-async.md
      03-handlers-and-streams.md
      04-config-reference.md
      05-api-reference.md
      06-examples.md
      07-faq.md
    curated/
      01-overview.md
      02-usage.md
      03-tool-reference.md
  en/
    # 与 zh 完全一一对应
```

`docs/zh/index.md` 与 `docs/en/index.md` 是站内文档首页，只列四本手册入口，并互指语言版本与 `README`。

## 8. 内容分层规范

### 8.1 手册首页

手册首页是本书唯一允许集中放链接的页面：一段导读 + 一份按顺序的章节目录。

### 8.2 手册正文页

不做“相关页面 / 下一步”链接墙，只保留必要的行内引用（例如指向配置说明或 CLI 参考）。

### 8.3 章节顺序

章节顺序完全由文件名数字前缀决定，见 §9.3。

## 9. 双语与排序策略

### 9.1 目录策略

- 中文路径：`docs/zh/...`
- 英文路径：`docs/en/...`
- 两套目录必须保持一一对应，文件数量与相对路径完全相同。

### 9.2 slug 策略

- `slug` 使用语义化英文路径，例如 `/docs/user-guide/install`。
- 中文与英文共享同一套 slug 逻辑，避免未来外链和 SEO 结构漂移。

### 9.3 章节顺序策略

- 正文文件名统一使用 `NN-` 数字前缀（`01-`、`02-`…）。
- 排序由前缀决定，`slug` 不含数字前缀，二者职责分离。
- 当前站点渲染按相对路径排序，因此实际 URL 含数字前缀（如 `/docs/zh/user-guide/02-install`）；`slug` 字段保留语义化路径作为规范值。

### 9.4 页面元信息

每篇文档统一包含以下 frontmatter：

```yaml
title:
slug:
lang:
summary:
status:
source:
last_reviewed:
```

`status` 取值：

- `stable` / `published`
- `draft`
- `beta`

## 10. 已上线范围

中文与英文各 27 页，均一一对应：

- `index.md`
- `user-guide/`：7 页
- `poc/`：9 页
- `sdk/`：7 页
- `curated/`：3 页

新增页面（重构时首次编写）：

- `user-guide/01-overview.md`、`user-guide/07-tips.md`
- `curated/01-overview.md`、`curated/02-usage.md`、`curated/03-tool-reference.md`

## 11. 实施阶段

### Phase 1：定骨架（已完成）

- 确定目录、slug、排序与双语规则。
- 精简根 `README` 的职责定义。

### Phase 2：迁核心（已完成）

- 将原有 `getting-started/`、`reference/`、`user-guide/`、`community/` 收敛进四本手册。
- 建立英文镜像目录并保持一一对应。

### Phase 3：收入口（已完成）

- `README.md` 与 `docs/README_CN.md` 收敛为四本手册入口，章节结构完全对称。
- `docs/{zh,en}/index.md` 收敛为四本手册目录页。
- 清理重复入口与失效链接。

### Phase 4：持续演进（进行中）

- 补齐英文正文与后续新增页面。
- 主仓库内容完善后，将结构与内容同步到 `afrog-website`。
- 形成“功能变更必须附带文档更新”的维护流程。

## 12. 验收标准

- `README.md` 与 `docs/README_CN.md` 只各自分发到四本手册，章节结构一致。
- 中文目录结构完整可导航，且与英文一一对应。
- 站内相对链接全部有效（当前共 228 个链接，0 失效）。
- 每本手册只有首页保留集中入口，正文页不再堆链接。
- Wiki 中的核心入口已被替换为新文档站链接。
- `README` 不再重复大段说明性内容。

## 13. 风险与控制

### 13.1 风险：迁移周期内出现新旧入口并存

控制方式：旧入口保留说明并跳转，迁移后及时清理。

### 13.2 风险：英文版长期缺位

控制方式：强制建立英文同路径文件，并在校验中检查两侧目录一致性。

### 13.3 风险：教程继续充当参考手册

控制方式：以目录分层约束内容类型，Review 时检查是否把参数定义混进教程页。

### 13.4 风险：数字前缀污染 slug

控制方式：`slug` 保持语义化路径，数字前缀只用于排序，不作为对外规范 URL。

## 14. 后续事项

1. **同步到 `afrog-website`**（待主仓库内容完善后）：
   - 在 `SECTION_LABELS` / `SECTION_ORDER` 中新增 `curated` 分组；
   - 按新的四本手册结构校对分节标题与顺序；
   - 确认新增页面在站内可正常渲染。
2. 补齐英文正文与后续新增页面。
3. 建立文档 CI 校验：中英文目录一致性、站内链接有效性。
4. 处理 `afrog.wiki` 的历史入口跳转。
