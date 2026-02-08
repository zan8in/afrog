# Afrog 官方教程(6)：开源贡献 - 成为 Contributor

> “一个人可以走得很快，但一群人才能走得更远。” —— 加入 Afrog 社区，共建安全生态。

大家好，这里是 **Afrog 官方**。
这是《Afrog 从入门到入土》系列的最后一期。
如果你已经跟着教程走到了这里，相信你已经具备了独立挖掘漏洞并编写 PoC 的能力。
如果你写出了一个很棒的 PoC，为什么不把它贡献给社区，让数千名安全研究员受益，并在这个优秀的开源项目上留下你的名字呢？

今天，我们来聊聊**如何提交一个高质量的 Pull Request (PR)**。

## 🏆 什么是“高质量”的 PoC？

在 Afrog 仓库中，我们对 PoC 的质量有着严格的要求。审核员在 Review 代码时，主要看这几点：

### 1. 误报率 (False Positive)
这是底线。一个误报的 PoC 会浪费无数人的时间。
- **坏例子**：只判断 `response.status == 200`。
- **好例子**：`response.status == 200 && response.body.bcontains(b"specific_string") && response.headers["server"].icontains("Tomcat")`。
- **建议**：尽量使用**多重特征组合**判断（状态码 + 关键词 + Header）。

### 2. 通用性
你的 PoC 是只能打本地环境，还是通杀全网？
- 避免硬编码 IP 地址或特定域名。
- 使用 `{{Hostname}}` 等变量代替写死的 Host。

### 3. 规范命名
- 文件名应与 ID 一致。
- 推荐格式：`CVE-2023-xxxx.yaml` 或 `CNVD-2023-xxxx.yaml`。
- `info` 里的 `severity` 必须准确（不要把 Info 标成 Critical）。

---

## 🚀 提交 PR 的流程

### 第一步：Fork 仓库
在 GitHub 上访问 [https://github.com/zan8in/afrog](https://github.com/zan8in/afrog)，点击右上角的 **Fork** 按钮，把项目复制到你自己的账号下。

### 第二步：添加 PoC
在你的仓库里（通常是 `pocs/afrog-pocs` 目录），新建你的 YAML 文件。
例如 `pocs/afrog-pocs/CVE/2023/CVE-2023-9999.yaml`。

### 第三步：本地测试（至关重要！）
在提交前，请务必在本地用 `-P` 参数测试通过。
```bash
afrog -t http://your-test-target.com -P ./your-new-poc.yaml
```
确保它能扫出来，且没有报错。

### 第四步：提交 Commit
```bash
git add .
git commit -m "Add CVE-2023-9999 PoC"
git push origin main
```

### 第五步：发起 Pull Request
回到 GitHub 你的仓库页面，点击 **Contribute** -> **Open Pull Request**。
在描述里写上：
- 这个 PoC 是测什么的？
- 是否经过测试？（最好附上本地测试成功的截图）
- 参考链接（Reference）。

---

## 🎁 贡献者的回报

1.  **荣誉**：你的头像会出现在 Afrog 的 README [Contributors](https://github.com/zan8in/afrog#poc-contributors) 列表中。
2.  **成长**：与顶尖的安全研究员交流代码，学习更优雅的写法。
3.  **社区认可**：在面试或晋升时，拥有开源项目的贡献记录是一个巨大的加分项。

---

## 👋 结语

《Afrog 从入门到入土》系列教程到这里就正式完结了。
从安装配置，到命令行参数，再到 PoC 的编写与进阶，希望这些内容能成为你安全路上的垫脚石。

Afrog 还在快速迭代中，我们的目标是做**最好用的漏洞扫描器**。
如果你在使用中遇到 Bug，或者有好的功能建议，欢迎在 GitHub Issues 提问。

**感谢每一位用户的支持，感谢每一位贡献者的付出。**

Stay Hungry, Stay Foolish.
我们 GitHub 见！

---
*本文由 Afrog 官方原创，欢迎转发分享。*
