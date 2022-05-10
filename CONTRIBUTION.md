# Afrog-PoC 贡献指南

为 afrog-poc 贡献 PoC 有两种方法

## 方法1：提交 Issues

#### 第一步: 查找现有 PoC

- 在创建新 PoC 之前查看[现有 PoC 库](https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs)
- 查看 [GitHub 问题](https://github.com/zan8in/afrog/issues)和[拉取请求](https://github.com/zan8in/afrog/pulls)部分中的现有 PoC 以避免重复
- 查看 [PoC 语法指南](https://github.com/zan8in/afrog/blob/main/pocs/afrog-pocs/README.md)

### 第二步：编写 Issues

- 浏览器打开提交 issues 网址：[ISSUES 网址](https://github.com/zan8in/afrog/issues)

- 然后点击右上角`New Issues`按钮
- 填写`title` ，比如：CVE-2022-1234
- 然后，内容填写 `cve-2020-1234.yaml`代码
- 接着，选择`label`选择 `afrog-poc`

- 最后，点击`Submit new issue`按钮

![](https://github.com/zan8in/afrog/blob/main/images/icon-1.png)

## 方法2：Pull Request

#### 第一步: 查找现有 PoC

- 在创建新 PoC 之前查看[现有 PoC 库](https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs)
- 查看 [GitHub 问题](https://github.com/zan8in/afrog/issues)和[拉取请求](https://github.com/zan8in/afrog/pulls)部分中的现有 PoC 以避免重复
- 查看 [PoC 语法指南

### 第二步：Fork 项目

点击 afrog 项目 `fork` 按钮

![](https://github.com/zan8in/afrog/blob/main/images/con-2.png)

```
git clone https://github.com/<your-username>/afrog
cd afrog
git remote add upstream https://github.com/zan8in/afrog
```

- 如果您已经`fork`项目，请在工作之前更新您的副本。

```
git remote update
git checkout master
git rebase upstream/master
```

### 第三步：创建你的 afrog branch

创建一个`new branch`

```
git checkout -b afrog_branch_name
```

### 第四步：编写和提交 PoC

- 创建和编写你的 PoC
- 添加到你刚刚创建的 `branch`

```
git add .
git commit -m "Added CVE-2022-1234.YAML PoC"
```

### 第五步：Push 到你的远程(forked)仓库

```
git push -u origin afrog_branch_name
```

### 第五步：Pull Request

- 浏览器打开你的 Github 仓库
- 点击 `Pull Request`
- 再点击`New pull request`

![](https://github.com/zan8in/afrog/blob/main/images/con-3.png)

- `compare`选择你创建的新`branch`（下图）
- 再点击`Create pull request`（下图）

![](https://github.com/zan8in/afrog/blob/main/images/con-5.png)

- 填写`title`和`content`，点击`Create pull request `按钮（下图）

![](https://github.com/zan8in/afrog/blob/main/images/con-6.png)

至此，您的`Pull Request`已提交，等待版主审核合并。

