# afrog 文档迁移清单

## 1. 说明

本清单记录 `afrog` 文档向四本手册结构迁移的实际结果，用于：

- 追溯每一份旧文档的归宿。
- 明确“保留、移动、重命名、重写、归档”等处理方式。
- 记录尚未完成的迁移项。

新结构以 `docs/zh/` 为主，英文版按同路径镜像创建 `docs/en/`。两侧目录必须一一对应。

## 2. 处理动作定义

- `重命名`：内容不变，仅按章节顺序加数字前缀。
- `移动`：内容不变，仅调整所属目录。
- `合并`：多篇旧文档合并进同一篇新文档。
- `重写`：入口页按新结构重新编写。
- `新增`：重构时首次编写的页面。
- `归档`：保留历史内容，但不再作为权威入口，也不进入站点导航。

## 3. 新文档目标结构

```text
docs/{zh,en}/
  index.md                  # 四本手册目录页（站内文档首页）
  user-guide/               # ① 使用指南
    01-overview.md
    02-install.md
    03-first-scan.md
    04-cli-options.md
    05-configuration.md
    06-output-and-report.md
    07-tips.md
  poc/                      # ② PoC 编写指南
    01-quickstart.md
    02-syntax.md
    03-helper-functions.md
    04-requires.md
    05-brute.md
    06-oob.md
    07-raw-http.md
    08-tcp.md
    09-contributors.md
  sdk/                      # ③ SDK 使用指南
    01-quickstart.md
    02-sync-and-async.md
    03-handlers-and-streams.md
    04-config-reference.md
    05-api-reference.md
    06-examples.md
    07-faq.md
  curated/                  # ④ Curated PoC
    01-overview.md
    02-usage.md
    03-tool-reference.md
```

## 4. 迁移总表（已完成）

以下路径同样适用于 `docs/zh/` 与 `docs/en/`。

| 旧路径（相对 `docs/{zh,en}/`） | 新路径 | 处理方式 | 备注 |
| --- | --- | --- | --- |
| `getting-started/install.md` | `user-guide/02-install.md` | 移动 + 重命名 | 并入使用指南 |
| `getting-started/first-scan.md` | `user-guide/03-first-scan.md` | 移动 + 重命名 | 并入使用指南 |
| `reference/cli-options.md` | `user-guide/04-cli-options.md` | 合并 + 移动 | `reference/` 目录取消 |
| `user-guide/configuration.md` | `user-guide/05-configuration.md` | 重命名 | — |
| `user-guide/output-and-report.md` | `user-guide/06-output-and-report.md` | 重命名 | — |
| `community/contributors.md` | `poc/09-contributors.md` | 移动 | 作为 PoC 手册附录 |
| `poc/quickstart.md` | `poc/01-quickstart.md` | 重命名 | PoC 手册首页 |
| `poc/syntax.md` | `poc/02-syntax.md` | 重命名 | — |
| `poc/helper-functions.md` | `poc/03-helper-functions.md` | 重命名 | — |
| `poc/requires.md` | `poc/04-requires.md` | 重命名 | — |
| `poc/brute.md` | `poc/05-brute.md` | 重命名 | — |
| `poc/oob.md` | `poc/06-oob.md` | 重命名 | — |
| `poc/raw-http.md` | `poc/07-raw-http.md` | 重命名 | — |
| `poc/tcp.md` | `poc/08-tcp.md` | 重命名 | — |
| `sdk/quickstart.md` | `sdk/01-quickstart.md` | 重命名 | SDK 手册首页 |
| `sdk/sync-and-async.md` | `sdk/02-sync-and-async.md` | 重命名 | — |
| `sdk/handlers-and-streams.md` | `sdk/03-handlers-and-streams.md` | 重命名 | — |
| `sdk/config-reference.md` | `sdk/04-config-reference.md` | 重命名 | — |
| `sdk/api-reference.md` | `sdk/05-api-reference.md` | 重命名 | — |
| `sdk/examples.md` | `sdk/06-examples.md` | 重命名 | — |
| `sdk/faq.md` | `sdk/07-faq.md` | 重命名 | — |
| `index.md` | `index.md` | 重写 | 收敛为四本手册目录页 |

已删除的空目录：`getting-started/`、`reference/`、`community/`。

## 5. 新增页面（已完成）

| 新路径 | 内容 |
| --- | --- |
| `user-guide/01-overview.md` | 使用指南开篇：afrog 是什么、能做什么、本书目录 |
| `user-guide/07-tips.md` | 实战技巧：目标输入、资产探测、性能与稳定性、OOB、输出、断点续扫 |
| `curated/01-overview.md` | curated PoC 的定位、与内置 PoC 的区别、接入前置条件 |
| `curated/02-usage.md` | 在 afrog 中启用 / 关闭 / 更新 curated PoC |
| `curated/03-tool-reference.md` | `afrog-curated` 命令、环境变量与本地文件 |

## 6. 仓库门面迁移（已完成）

| 旧入口 | 新入口 | 处理方式 |
| --- | --- | --- |
| `README.md` 的 5 个文档链接 | 四本手册入口（英文） | 重写 |
| `docs/README_CN.md` 的 6 个文档链接 + 「示例 / 项目链接」 | 与 `README.md` 完全对称的章节结构（四本手册入口，中文） | 重写 |

两份 README 现在包含相同的章节集合：项目简介、安装、快速开始、文档入口、PoC 贡献者、讨论群、404Starlink、免责声明。

## 7. 历史正文归档（保留，不进入站点导航）

以下文件位于 `docs/` 根目录或独立目录，不在 `docs/{zh,en}/` 下，因此不会被站点遍历，仅作为历史归档保留：

| 历史文件 | 正文去向 | 处理方式 |
| --- | --- | --- |
| `docs/afrog-poc-guide.md` | `docs/{zh,en}/poc/*` | 已拆分，保留归档 |
| `docs/afrog-helper-function.md` | `docs/{zh,en}/poc/03-helper-functions.md` | 已拆分，保留归档 |
| `docs/requires-gating-guide.md` | `docs/{zh,en}/poc/04-requires.md` | 已拆分，保留归档 |
| `docs/SDK使用指南_中文.md` | `docs/zh/sdk/*` | 已拆分，保留归档 |
| `docs/SDK_Usage_Guide_English.md` | `docs/en/sdk/*` | 已拆分，保留归档 |
| `docs/TCP/tcp-ssl-multi-step-session.md` | `docs/{zh,en}/poc/08-tcp.md` | 已合并，保留归档 |
| `docs/tutorial/rumen-dao-rutu/*` | 部分内容已并入四本手册 | 保留归档 |
| `docs/tutorial/series-params-to-principles/*` | 部分内容已并入四本手册 | 保留归档 |
| `afrog.wiki/*` | `docs/{zh,en}/*` | 待处理（见 §9） |

## 8. 校验结果

- `docs/zh` 与 `docs/en` 各 27 个 Markdown 文件，相对路径一一对应。
- `docs/{zh,en}` 内共 228 个链接，其中 212 个站内相对链接全部有效，0 失效。
- 被移动页面的 `frontmatter.slug` 已更新为新的语义化路径（不含数字前缀）。
- `frontmatter.source` 中指向旧路径的引用已同步更新。

## 9. 待处理事项

1. `afrog.wiki/*` 的历史入口改为跳转或归档说明。
2. `docs/{zh,en}` 之外的归档文件在确认无引用后可考虑清理。
3. 主仓库内容完善后，将本结构与新增页面同步到 `afrog-website`：

   - 在 `SECTION_LABELS` / `SECTION_ORDER` 中新增 `curated` 分组；
   - 校对分节标题与顺序是否与四本手册一致；
   - 验证新增页面在站点内正常渲染。

4. 建立文档 CI 校验：中英文目录一致性、站内链接有效性。
