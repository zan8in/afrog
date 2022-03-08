@REM SET CGO_ENABLED=0
@REM SET GOOS=windows
@REM SET GOARCH=amd64
@REM go build -v -a -o release/amd64/afrog_windows_amd64.exe


SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
go build  -v -a -o release/amd64/afrog_linux_amd64


@REM SET CGO_ENABLED=0
@REM SET GOOS=darwin
@REM SET GOARCH=amd64
@REM go build -v -a -o release/amd64/afrog_darwin_amd64

@REM cd ./release/amd64/

@REM C:/zip/zip.exe -r ./afrog_windows_amd64.zip ./afrog_windows_amd64.exe
tar -zcvf afrog_linux_amd64.tar.gz afrog_linux_amd64
@REM tar -zcvf afrog_darwin_amd64.tar.gz afrog_darwin_amd64
