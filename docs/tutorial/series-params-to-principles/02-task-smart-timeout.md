# #02：批量漏扫时，建议默认带上 `--task-smart-timeout`

如果你经常批量跑资产，真正拖慢扫描的，通常不是大多数正常任务，而是少数又慢又长的尾巴任务。

`--task-smart-timeout` 的作用就一句话：

- 按 `PoC` 复杂度动态分配单任务超时
- 普通 `PoC` 更短，复杂 `PoC` 更宽松
- 尽量减少长尾拖慢全局

所以我的建议很直接：

- **只要是批量漏扫，优先开 `--task-smart-timeout`**

---

## 先记住这三条

最常用：

```bash
afrog -T targets.txt --task-smart-timeout
```

想看谁在拖慢：

```bash
afrog -T targets.txt --task-smart-timeout -pedm
```

已知这批目标很慢，再加固定兜底：

```bash
afrog -T targets.txt --task-smart-timeout --task-hard-timeout-sec 180 -pedm
```

---

## 它和固定超时的区别

固定硬超时是：

```bash
afrog -T targets.txt --task-hard-timeout-sec 120
```

意思是所有 `target × PoC` 一刀切最多跑 `120s`。

问题也很明显：

- 普通 `PoC` 可能给太多
- 复杂 `PoC` 可能又不够

而 `--task-smart-timeout` 不是一刀切，而是按 `PoC` 内容估算预算，更适合混合型 `PoC` 库和批量资产场景。

结论只有一句：

- **优先用 `--task-smart-timeout`，固定超时只做补充兜底**

---

## 它到底“聪明”在哪

Afrog 会根据 `PoC` 特征估算超时，比如：

- `rules` 数量
- 是否有 `oobCheck(...)`
- 是否有 `sleep()`、`WAITFOR DELAY`
- 是否使用 `brute`
- 是普通 HTTP、网络协议类，还是 `go` `PoC`

这意味着：

- 普通 HTTP `PoC` 不会被给太夸张的超时
- `OOB`、`brute`、`go`、网络类 `PoC` 会更宽松

它不是“统一缩短扫描”，而是“让不同 `PoC` 的超时更接近真实复杂度”。

---

## 哪些场景最该开

- 批量资产漏扫
- 公网目标质量参差不齐
- 明显存在慢目标、慢 `PoC`

如果只是手工临时验证、目标很少，可以不开。  
但只要进入“跑批”场景，我建议把它当成默认习惯。

---

## 为什么建议配合 `-pedm`

`-pedm` 不是必须，但很有用，因为它能帮你看到：

- 哪些任务在慢跑
- 哪些任务触发了超时
- 哪个 `target + PoC` 最拖尾

实用组合：

```bash
afrog -T targets.txt --task-smart-timeout -pedm --pedm-slow-sec 30
```

---

## 最后结论

如果你只想记住一句话，那就是：

- **批量漏扫时，尽量默认带上 `--task-smart-timeout`**

推荐直接用这条：

```bash
afrog -T targets.txt --task-smart-timeout
```

想顺便观察慢任务，就用这条：

```bash
afrog -T targets.txt --task-smart-timeout -pedm
```

---

## 下期预告

**#03：`--resume` 断点续扫为什么需要，恢复边界在哪里。**
