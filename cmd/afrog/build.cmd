SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
go build -v -a -o release/afrog_windows_amd64.exe


SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
go build  -v -a -o release/afrog_linux_amd64

SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=arm
go build  -v -a -o release/afrog_linux_arm64

SET CGO_ENABLED=0
SET GOOS=darwin
SET GOARCH=amd64
go build -v -a -o release/afrog_darwin_amd64

cd ./release/

C:/zip/zip.exe -r ./afrog_windows_amd64.zip ./afrog_windows_amd64.exe
tar -zcvf afrog_linux_amd64.tar.gz afrog_linux_amd64
tar -zcvf afrog_darwin_amd64.tar.gz afrog_darwin_amd64
tar -zcvf afrog_linux_arm64.tar.gz afrog_linux_arm64