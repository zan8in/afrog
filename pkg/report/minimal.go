package report

import (
	"fmt"
	"strings"

	timeutil "github.com/zan8in/pins/time"
)

func (report *Report) minimalHtml(line string) string {
	htResult := report.Result
	if htResult == nil {
		return ""
	}

	// 简约风格的漏洞条目
	title := fmt.Sprintf(`<div class="vuln-item">
		<div class="vuln-header" onclick="toggleDetails(this)">
			<span class="vuln-id">%s</span>
			<span class="vuln-name">%s</span>
			<span class="severity %s">%s</span>
			<span class="target">%s</span>
			<span class="toggle-icon">▼</span>
		</div>`,
		line, htResult.PocInfo.Id, htResult.PocInfo.Info.Severity,
		strings.ToUpper(htResult.PocInfo.Info.Severity), htResult.Target)

	// 漏洞详细信息
	info := fmt.Sprintf(`<div class="vuln-details">
			<div class="info-section">
				<h4>基本信息</h4>
				<p><strong>名称:</strong> %s</p>
				<p><strong>作者:</strong> %s</p>
				<p><strong>严重级别:</strong> %s</p>`,
		htResult.PocInfo.Info.Name, htResult.PocInfo.Info.Author, htResult.PocInfo.Info.Severity)

	if len(htResult.PocInfo.Info.Description) > 0 {
		description := strings.ReplaceAll(htResult.PocInfo.Info.Description, "\n", "<br/>")
		info += fmt.Sprintf(`<p><strong>描述:</strong> %s</p>`, description)
	}

	if len(htResult.PocInfo.Info.Reference) > 0 {
		info += `<p><strong>参考链接:</strong></p><ul>`
		for _, rv := range htResult.PocInfo.Info.Reference {
			info += fmt.Sprintf(`<li><a href="%s" target="_blank">%s</a></li>`, rv, rv)
		}
		info += `</ul>`
	}

	if len(htResult.PocInfo.Info.Affected) > 0 {
		affected := strings.ReplaceAll(htResult.PocInfo.Info.Affected, "\n", "<br/>")
		info += fmt.Sprintf(`<p><strong>影响范围:</strong> %s</p>`, affected)
	}

	if len(htResult.PocInfo.Info.Solutions) > 0 {
		solutions := strings.ReplaceAll(htResult.PocInfo.Info.Solutions, "\n", "<br/>")
		info += fmt.Sprintf(`<p><strong>解决方案:</strong> %s</p>`, solutions)
	}

	if len(htResult.PocInfo.Info.Created) > 0 {
		info += fmt.Sprintf(`<p><strong>创建时间:</strong> %s</p>`, htResult.PocInfo.Info.Created)
	}

	info += `</div>`

	// 请求响应详情
	body := ""
	for _, v := range htResult.AllPocResult {
		if !v.IsVul {
			continue
		}

		reqraw := xssfilter(string(v.ResultRequest.GetRaw()))
		respraw := xssfilter(string(v.ResultResponse.GetRaw()))
		fullurl := xssfilter(v.FullTarget)

		body += fmt.Sprintf(`
			<div class="request-response">
				<div class="url-section">
					<a href="%s" target="_blank" class="target-url">%s</a>
					<span class="response-time">%d ms</span>
				</div>
				<div class="req-resp-container">
					<div class="request-section">
						<h5>请求 <button class="copy-btn" onclick="copyContent(this)">复制</button></h5>
						<pre class="code-block">%s</pre>
					</div>
					<div class="response-section">
						<h5>响应 <button class="copy-btn" onclick="copyContent(this)">复制</button></h5>
						<pre class="code-block">%s</pre>
					</div>
				</div>
			</div>`,
			fullurl, fullurl, v.ResultResponse.GetLatency(), reqraw, respraw)
	}

	footer := `		</div>
	</div>`

	return title + info + body + footer
}

func minimalHeader() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Afrog 漏洞扫描报告 - 简约版</title>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
			line-height: 1.6;
			color: #333;
			background-color: #f8f9fa;
			padding: 20px;
		}

		.container {
			max-width: 1200px;
			margin: 0 auto;
		}

		.header {
			text-align: center;
			margin-bottom: 30px;
			padding: 20px;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
			border-radius: 10px;
			box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
		}

		.header h1 {
			font-size: 2.5em;
			margin-bottom: 10px;
		}

		.header p {
			font-size: 1.1em;
			opacity: 0.9;
		}

		.vuln-item {
			background: white;
			border-radius: 8px;
			margin-bottom: 20px;
			box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
			overflow: hidden;
			transition: box-shadow 0.3s ease;
		}

		.vuln-item:hover {
			box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
		}

		.vuln-header {
			padding: 15px 20px;
			cursor: pointer;
			display: flex;
			align-items: center;
			gap: 15px;
			background: #f8f9fa;
			border-bottom: 1px solid #e9ecef;
			transition: background-color 0.2s ease;
		}

		.vuln-header:hover {
			background: #e9ecef;
		}

		.vuln-id {
			font-weight: bold;
			color: #495057;
			min-width: 60px;
		}

		.vuln-name {
			flex: 1;
			font-weight: 600;
			color: #212529;
		}

		.severity {
			padding: 4px 12px;
			border-radius: 20px;
			font-size: 0.85em;
			font-weight: bold;
			text-transform: uppercase;
		}

		.severity.critical {
			background: #dc3545;
			color: white;
		}

		.severity.high {
			background: #fd7e14;
			color: white;
		}

		.severity.medium {
			background: #ffc107;
			color: #212529;
		}

		.severity.low {
			background: #20c997;
			color: white;
		}

		.severity.info {
			background: #17a2b8;
			color: white;
		}

		.target {
			color: #6c757d;
			font-family: 'Consolas', 'Monaco', monospace;
			font-size: 0.9em;
			max-width: 300px;
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}

		.toggle-icon {
			transition: transform 0.3s ease;
			color: #6c757d;
		}

		.vuln-details {
			padding: 20px;
			display: none;
		}

		.vuln-details.show {
			display: block;
		}

		.info-section {
			margin-bottom: 25px;
		}

		.info-section h4 {
			color: #495057;
			margin-bottom: 15px;
			padding-bottom: 8px;
			border-bottom: 2px solid #e9ecef;
		}

		.info-section p {
			margin-bottom: 8px;
		}

		.info-section ul {
			margin-left: 20px;
			margin-top: 5px;
		}

		.info-section a {
			color: #007bff;
			text-decoration: none;
		}

		.info-section a:hover {
			text-decoration: underline;
		}

		.request-response {
			margin-top: 20px;
			border: 1px solid #e9ecef;
			border-radius: 6px;
			overflow: hidden;
		}

		.url-section {
			padding: 10px 15px;
			background: #f8f9fa;
			border-bottom: 1px solid #e9ecef;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.target-url {
			color: #007bff;
			text-decoration: none;
			font-family: 'Consolas', 'Monaco', monospace;
		}

		.target-url:hover {
			text-decoration: underline;
		}

		.response-time {
			color: #6c757d;
			font-size: 0.9em;
		}

		.req-resp-container {
			display: grid;
			grid-template-columns: 1fr 1fr;
			gap: 1px;
			background: #e9ecef;
			min-width: 0; /* 防止grid项目撑开容器 */
		}

		.request-section, .response-section {
			background: white;
			padding: 15px;
			min-width: 0; /* 防止内容撑开容器 */
			overflow: hidden; /* 确保内容不会溢出 */
		}

		.request-section h5, .response-section h5 {
			margin-bottom: 10px;
			color: #495057;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.code-block {
			background: #f8f9fa;
			border: 1px solid #e9ecef;
			border-radius: 4px;
			padding: 12px;
			font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
			font-size: 0.85em;
			line-height: 1.4;
			overflow: auto; /* 同时处理水平和垂直滚动 */
			max-height: 400px;
			max-width: 100%; /* 限制最大宽度 */
			white-space: pre; /* 保持原始格式但不自动换行 */
			word-break: break-all; /* 强制长单词换行 */
		}

		.copy-btn {
			background: #007bff;
			color: white;
			border: none;
			padding: 4px 8px;
			border-radius: 4px;
			font-size: 0.75em;
			cursor: pointer;
			transition: background-color 0.2s ease;
		}

		.copy-btn:hover {
			background: #0056b3;
		}

		.footer {
			text-align: center;
			margin-top: 40px;
			padding: 20px;
			color: #6c757d;
			border-top: 1px solid #e9ecef;
		}

		@media (max-width: 768px) {
			.vuln-header {
				flex-direction: column;
				align-items: flex-start;
				gap: 8px;
			}

			.req-resp-container {
				grid-template-columns: 1fr;
			}

			.target {
				max-width: none;
			}
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🔍 Afrog 漏洞扫描报告</h1>
			<p>简约版 - 生成时间: ` + timeutil.Format(timeutil.Format_1) + `</p>
		</div>

	<script>
		function toggleDetails(header) {
			const details = header.nextElementSibling;
			const icon = header.querySelector('.toggle-icon');
			
			if (details.classList.contains('show')) {
				details.classList.remove('show');
				icon.style.transform = 'rotate(0deg)';
			} else {
				details.classList.add('show');
				icon.style.transform = 'rotate(180deg)';
			}
		}

		function copyContent(button) {
			const codeBlock = button.parentElement.nextElementSibling;
			const text = codeBlock.textContent;
			
			navigator.clipboard.writeText(text).then(() => {
				const originalText = button.textContent;
				button.textContent = '已复制';
				button.style.background = '#28a745';
				
				setTimeout(() => {
					button.textContent = originalText;
					button.style.background = '#007bff';
				}, 2000);
			}).catch(err => {
				console.error('复制失败:', err);
				alert('复制失败，请手动复制');
			});
		}

		// 页面加载完成后的初始化
		document.addEventListener('DOMContentLoaded', function() {
			console.log('Afrog 简约报告模板加载完成');
		});
	</script>
`
}
