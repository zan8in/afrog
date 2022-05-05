<h1 align="center">afrog 使用指南</h1>

<p align="center" dir="auto">🐸喜欢请点赞🌟⭐，不迷路</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/tree/main/afrog-pocs">POC 仓库</a> •
  <a href="https://github.com/zan8in/afrog/blob/main/README_en.md">English Doc</a>
</p>

# 方法1：二进制安装（推荐）

① 下载压缩包 [前往下载](https://github.com/zan8in/afrog/releases)

- MacOS系统  `afrog_darwin_amd64.tar.gz `    
- Linux系统    `afrog_linux_amd64.tar.gz  `  
- MacOS M1系统  `afrog_linux_arm64.tar.gz` 
- Windows系统   `afrog_windows_amd64.zip `

②  解压压缩包

③ cd 解压目录

④ 启动

- linux 启动

```
./afrog_linux_amd64 -t example.com -o r.html
```

- windows 启动

```
afrog_windows_amd64.exe -t example.com -o r.html
```

- macos 启动

```
./afrog_darwin_amd64 -t example.com -o r.html
```

- macos m1 启动

```
./afrog_linux_arm64 -t example.com -o r.html
```



# 方法2：编译安装

首先下载源码

```
git clone https://github.com/zan8in/afrog
```

进入 afrog 目录

```
cd afrog
```

然后开始编译源码，操作系统不同，编译命令有所不同。

### ① Linux 编译

设置变量，分别执行下面三个命令

```
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
```

然后，执行编译命令

```
go build  -v -a -o afrog_linux_amd64 cmd/afrog/main.go
```

编译完成，afrog 目录内生成文件 `afrog_linux_amd64`

### ② Windows 编译

设置变量，分别执行下面三个命令

```
SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
```

然后，执行编译命令

```
go build -v -a -o afrog_windows_amd64.exe  cmd/afrog/main.go
```

编译完成，afrog 目录内生成文件 `afrog_windows_amd64`

### ③ MacOS 编译

设置变量，分别执行下面三个命令

```
SET CGO_ENABLED=0
SET GOOS=darwin
SET GOARCH=amd64
```

然后，执行编译命令

```
go build -v -a -o afrog_darwin_amd64  cmd/afrog/main.go
```

编译完成，afrog 目录内生成文件 `afrog_darwin_amd64`

### ④ Arm 架构系统（MacOS M1） 编译

设置变量，分别执行下面三个命令

```
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=arm
```

然后，执行编译命令

```
go build -v -a -o afrog_linux_arm64  cmd/afrog/main.go
```

编译完成，afrog 目录内生成文件 `afrog_linux_arm64`
