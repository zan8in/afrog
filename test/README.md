# Afrog SDK 测试示例

本目录包含了针对 www.baidu.com 的 Afrog SDK 扫描测试和示例代码。

## 文件说明

### baidu_scan_test.go
包含四个完整的测试用例：

1. **TestBaiduScan** - 基础扫描测试
   - 使用信息泄露和指纹识别POC
   - 包含详细的结果输出和统计信息
   - 配置了对目标友好的扫描参数

2. **TestBaiduScanWithProgress** - 带进度显示的扫描
   - 启用了进度条显示
   - 只使用指纹识别POC确保安全

3. **TestBaiduScanBasic** - 最简配置扫描
   - 演示最基础的SDK使用方法
   - 极简的配置和输出

4. **TestBaiduScanMultipleTargets** - 多目标扫描
   - 同时扫描多个百度子域名
   - 统计每个目标的扫描结果

### baidu_example.go
包含一个完整的使用示例函数 `ExampleBaiduScan()`，演示了：
- 基本的SDK初始化和配置
- 实时结果回调处理
- 扫描结果的详细输出

## 运行测试

### 运行所有测试
```bash
cd /Users/zhizhuo/Desktop/tools/afrog/源码/afrog/test
go test -v
```

### 运行特定测试
```bash
# 运行基础扫描测试
go test -v -run TestBaiduScan

# 运行带进度的扫描测试  
go test -v -run TestBaiduScanWithProgress

# 运行最简配置测试
go test -v -run TestBaiduScanBasic

# 运行多目标测试
go test -v -run TestBaiduScanMultipleTargets
```

## 配置说明

### 扫描参数
- **Concurrency**: 3-10 (低并发，避免对目标造成压力)
- **RateLimit**: 20-50 (限制请求速率)
- **Timeout**: 8-15秒 (适当的超时时间)
- **Severity**: "info,low" (只扫描低风险POC)

### POC选择
- 优先使用 `fingerprinting` 目录下的指纹识别POC
- 可选使用 `disclosure` 目录下的信息泄露POC
- 避免使用可能造成影响的漏洞POC

## 注意事项

1. **目标友好**: 所有测试都配置了较低的并发和请求频率，避免对百度服务器造成压力
2. **POC安全**: 主要使用指纹识别和信息泄露类POC，避免使用可能造成实际影响的漏洞POC
3. **路径配置**: POC路径使用相对路径，确保在项目目录下正确运行
4. **错误处理**: 包含完整的错误处理和资源清理

## 自定义扫描目标

如需扫描其他目标，只需修改 `options.Targets` 数组：

```go
options.Targets = []string{
    "https://your-target.com",
    "https://another-target.com",
}
```

## SDK功能演示

这些测试展示了 Afrog SDK 的主要功能：
- ✅ 扫描器创建和配置
- ✅ 多目标并发扫描  
- ✅ 实时结果回调处理
- ✅ 进度显示控制
- ✅ POC过滤和筛选
- ✅ 扫描结果统计和输出
- ✅ 资源管理和清理

通过这些示例，您可以快速了解如何在自己的项目中集成和使用 Afrog SDK。
