# #02：`--task-smart-timeout` 为什么值得你默认带上

> “真正拖慢漏扫的，往往不是 1 万个正常任务，而是那几十个又慢又长的尾巴任务。”

如果你经常批量跑资产，你大概率见过这些现象：

- 进度条长时间不动，看起来像“卡死”
- 某个目标上的某个 `PoC` 一跑就是几分钟，拖住整个批次
- 你不敢设置固定超时，怕把慢 `PoC` 直接切掉
- 你设置了固定超时，又担心 `OOB`、`brute`、`go` 类 `PoC` 被误杀

`--task-smart-timeout` 就是为这类问题设计的。

它不是简单的“给每个任务加个超时”，而是：

- 按 `PoC` 内容动态估算每个 `target × PoC` 任务应该跑多久
- 普通 `PoC` 给得更短，复杂 `PoC` 给得更宽松
- 减少“长尾卡住全局”的情况
- 同时尽量降低固定硬超时带来的误杀风险

---

## 这期讲哪些参数

- `--task-smart-timeout`：按 `PoC` 内容动态估算单任务硬超时
- `--task-hard-timeout-sec`：固定硬超时兜底
- `--task-timeout-visible-cap-sec`：普通 HTTP `PoC` 动态超时上限
- `--task-timeout-net-cap-sec`：`tcp/udp/ssl` `PoC` 动态超时上限
- `--task-timeout-go-cap-sec`：`go` `PoC` 动态超时上限
- `--pedm`：建议配合使用，用于观察慢任务和超时行为

---

## 一句话建议

- 跑批、SRC、巡检、红队资产漏扫：**强烈建议开启 `--task-smart-timeout`**
- 已知目标很慢、容易拖尾：再加 `--task-hard-timeout-sec`
- 想知道到底是谁在拖慢扫描：配 `--pedm`

最推荐的起手式：

```bash
afrog -T targets.txt --task-smart-timeout
```

更推荐的观察式：

```bash
afrog -T targets.txt --task-smart-timeout -pedm
```

如果你明确知道这批资产很慢：

```bash
afrog -T targets.txt --task-smart-timeout --task-hard-timeout-sec 180 -pedm
```

---

## 为什么我想推广你多用它

因为它解决的是 Afrog 在大规模漏扫里最真实的一类体验问题：

- 不是“有没有漏洞”
- 而是“同样的漏洞能力，能不能更稳、更快、更少被尾巴任务拖垮”

很多时候，真正让扫描体验变差的不是并发不够，不是速率太低，而是：

- 少数目标响应极慢
- 少数 `PoC` 本身请求链很长
- `OOB`、`brute`、`go` 类 `PoC` 天然就比普通 HTTP `PoC` 重
- 你又不敢一刀切给固定短超时

所以传统做法通常卡在两个极端：

- 不设超时：最完整，但长尾任务会把批量扫描拖得很难受
- 设固定超时：更可控，但容易误杀复杂 `PoC`

`--task-smart-timeout` 的价值就在这里：

- 它不是简单地“更激进”
- 而是尽量做到“该短的短，该长的长”

这就是为什么我更推荐你多用 `--task-smart-timeout`，而不是直接依赖固定的 `--task-hard-timeout-sec`。

---

## 它到底在“聪明”什么

Afrog 不会给所有任务统一一个时间，而是先分析 `PoC` 内容，再给每个 `PoC` 预算时间。

当前会考虑这些信号：

- `rules` 数量
- 是否存在 `oobCheck(...)`
- 是否存在显式 `sleep()`、`WAITFOR DELAY`、`before_sleep`
- 是否使用 `brute`
- `brute` 的变量个数、数组长度、`mode`
- 顶层 `expression` 的复杂度
- 请求体、请求头是否明显更重
- `PoC` 是普通 HTTP，还是 `tcp/udp/ssl`，还是 `go`

这意味着：

- 普通单规则 HTTP `PoC` 不会被给到离谱的高超时
- `brute` `PoC` 不会被当成普通单请求 `PoC`
- `OOB` `PoC` 会比普通 `PoC` 更宽松
- `go` / 网络类 `PoC` 会有更高上限

一句话理解：

- `--task-smart-timeout` 不是“统一缩短扫描”
- 而是“把超时预算分配得更像每个 `PoC` 的真实复杂度”

---

## 和固定硬超时有什么区别

### 1) 固定硬超时：简单粗暴

```bash
afrog -T targets.txt --task-hard-timeout-sec 120
```

含义很直接：

- 所有 `target × PoC` 最多跑 `120s`

优点：

- 好理解
- 好控时

缺点：

- 对普通 `PoC` 也许太宽
- 对复杂 `PoC` 也许太短

### 2) 智能超时：按 `PoC` 分配预算

```bash
afrog -T targets.txt --task-smart-timeout
```

含义是：

- 普通 `PoC` 用普通预算
- 复杂 `PoC` 用更高预算

优点：

- 更适合真实世界的混合型 `PoC` 库
- 更适合批量资产漏扫
- 更适合你“不想被长尾拖死，但也不想误杀复杂 `PoC`”的场景

我的建议很明确：

- **优先用 `--task-smart-timeout`**
- `--task-hard-timeout-sec` 只作为补充兜底

---

## 适合哪些场景

### 1) 批量资产漏扫

这是最推荐的场景。

你不可能手动盯每个慢任务，也不可能为每条 `PoC` 单独调超时。  
这时候 `--task-smart-timeout` 的收益最大。

推荐：

```bash
afrog -T targets.txt --task-smart-timeout
```

### 2) 公网目标质量参差不齐

公网资产很常见的问题是：

- 有的站很快
- 有的站半死不活
- 有的站被 WAF、限流、上游代理拖慢

这类场景下，长尾任务非常典型。

推荐：

```bash
afrog -T targets.txt --task-smart-timeout -pedm
```

### 3) 已知存在很多慢 `PoC`

比如：

- `brute`
- `OOB`
- `go`
- 网络协议类

这时候建议加一层固定兜底，避免极端长尾失控。

推荐：

```bash
afrog -T targets.txt --task-smart-timeout --task-hard-timeout-sec 180 -pedm
```

---

## 为什么建议配合 `-pedm`

虽然 `--task-smart-timeout` 可以单独用，但我非常建议你在批量跑的时候配上 `-pedm`。

因为 `-pedm` 能让你看到：

- 哪些 `PoC` 正在慢跑
- 哪些任务触发了超时
- 哪个 `target + PoC` 最拖尾

而且现在 Afrog 已经做了控制：

- 只有开启 `-pedm` 时，才会打印 `TASK-TIMEOUT` 这类监控日志
- 不开 `-pedm` 时，超时仍然生效，但不会污染正常漏洞结果输出

所以最实用的组合通常是：

```bash
afrog -T targets.txt --task-smart-timeout -pedm --pedm-slow-sec 30
```

---

## 三套推荐打法

### 1) 保守打法：结果完整优先

适合：

- 小批量验证
- 对总耗时不敏感
- 更担心误杀

```bash
afrog -T targets.txt
```

### 2) 推荐打法：批量漏扫默认建议

适合：

- 大多数日常使用场景
- 想提升整体体验，但不想太激进

```bash
afrog -T targets.txt --task-smart-timeout
```

### 3) 控制打法：尾部长任务明显时

适合：

- 公网跑批
- 明显存在慢目标、慢 `PoC`
- 希望把整体时长控制在更稳的范围

```bash
afrog -T targets.txt --task-smart-timeout --task-hard-timeout-sec 180 -pedm
```

---

## 常见误区

### 1) “开启智能超时，会不会更容易漏报？”

有可能，但相比固定硬超时，它已经是更稳的方案。

因为它不是一刀切，而是按 `PoC` 内容分配预算。

### 2) “那我是不是就不用 `--task-hard-timeout-sec` 了？”

多数情况下，是的。  
先用 `--task-smart-timeout` 就够了。

只有当你明确发现：

- 这批目标整体很慢
- 长尾任务还是太多

再考虑加固定兜底。

### 3) “不开 `-pedm` 会不会失效？”

不会。

- `--task-smart-timeout` 仍然生效
- 只是不会打印监控日志

### 4) “为什么不把它做成默认开启？”

因为安全扫描工具的默认行为要尽量稳、尽量兼容历史预期。  
但从实战推荐角度，我依然认为：

- **你应该主动多用 `--task-smart-timeout`**

---

## 排障建议

如果你开启后发现问题，可以这样判断：

- 进度条更顺畅、尾巴更少：说明它起效了
- 某些 `PoC` 总是命中超时：配 `-pedm` 看具体是谁
- 某类 `PoC` 经常被切掉：再考虑是否加 `--task-hard-timeout-sec`
- 个别 `go` `PoC` 还是偏慢：这是后续值得继续优化的重点

推荐排障命令：

```bash
afrog -T targets.txt --task-smart-timeout -pedm --pedm-slow-sec 30 --pedm-summary-top 10
```

---

## 最后给你的推广结论

如果你是 Afrog 的日常用户，我的建议很直接：

- 手工临时验证，可以不开
- 但只要进入“批量漏扫”场景，**尽量把 `--task-smart-timeout` 养成习惯**

因为它带来的不是单点参数收益，而是整批任务的体验升级：

- 更少长尾拖累
- 更少“看起来卡死”
- 更适合混合型 `PoC` 库
- 比固定硬超时更稳

推荐你直接记住这一条：

```bash
afrog -T targets.txt --task-smart-timeout
```

如果你愿意再多看一点运行细节，就用这条：

```bash
afrog -T targets.txt --task-smart-timeout -pedm
```

---

## 下期预告

下一期继续讲“扫描稳定性与可恢复性”：

**#03：`--resume` 断点续扫为什么需要，恢复边界在哪里。**
