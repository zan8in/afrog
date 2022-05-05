<h1 align="center">afrog Guide</h1>

<p align="center">A tool for finding vulnerabilities. <br/>🐸Like please tag stars🌟⭐</p>

<p align="center" dir="auto">
  <a href="https://github.com/zan8in/afrog/tree/main/afrog-pocs">PoC directory</a> •
  <a href="https://github.com/zan8in/afrog">中文文档</a>
</p>

# Method 1: Binary installation (recommended)

① Download the compressed package [Go to download](https://github.com/zan8in/afrog/releases)

- MacOS  `afrog_darwin_amd64.tar.gz `    
- Linux    `afrog_linux_amd64.tar.gz  `  
- MacOS M1  `afrog_linux_arm64.tar.gz` 
- Windows   `afrog_windows_amd64.zip `

②  Unzip the compressed package

③ cd unzip directory

④ run afrog

- linux boot

```
./afrog_linux_amd64 -t example.com -o r.html
```

- windows boot

```
afrog_windows_amd64.exe -t example.com -o r.html
```

- macos boot

```
./afrog_darwin_amd64 -t example.com -o r.html
```

- macos m1 boot

```
./afrog_linux_arm64 -t example.com -o r.html
```



# Method 2: Compile and install

First download the source code

```
git clone https://github.com/zan8in/afrog
```

Go to the afrog directory

```
cd afrog
```

Then start compiling the source code. Different operating systems have different compilation commands.

### ① Compilation for Linux

To set the variable, execute the following three commands respectively

```
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
```

Then, execute the compile command

```
go build  -v -a -o afrog_linux_amd64 cmd/afrog/main.go
```

The compilation is complete, and the files are generated in the afrog directory `afrog_linux_amd64`

### ② Compilation for Windows 

To set the variable, execute the following three commands respectively

```
SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
```

Then, execute the compile command

```
go build -v -a -o afrog_windows_amd64.exe  cmd/afrog/main.go
```

The compilation is complete, and the files are generated in the afrog directory `afrog_windows_amd64`

### ③ Compilation for MacOS 

To set the variable, execute the following three commands respectively

```
SET CGO_ENABLED=0
SET GOOS=darwin
SET GOARCH=amd64
```

Then, execute the compile command

```
go build -v -a -o afrog_darwin_amd64  cmd/afrog/main.go
```

The compilation is complete, and the files are generated in the afrog directory `afrog_darwin_amd64`

### ④ Compilation for Arm Architecture system（MacOS M1）

To set the variable, execute the following three commands respectively

```
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=arm
```

Then, execute the compile command

```
go build -v -a -o afrog_linux_arm64  cmd/afrog/main.go
```

The compilation is complete, and the files are generated in the afrog directory `afrog_linux_arm64`
