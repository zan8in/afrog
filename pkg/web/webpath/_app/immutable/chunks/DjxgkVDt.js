import{m as M,l as t,e as w}from"./C92a979i.js";globalThis.MonacoEnvironment={getWorkerUrl:function(d,m){const b={json:"monaco-editor/esm/vs/language/json/json.worker.js",css:"monaco-editor/esm/vs/language/css/css.worker.js",scss:"monaco-editor/esm/vs/language/css/css.worker.js",less:"monaco-editor/esm/vs/language/css/css.worker.js",html:"monaco-editor/esm/vs/language/html/html.worker.js",handlebars:"monaco-editor/esm/vs/language/html/html.worker.js",razor:"monaco-editor/esm/vs/language/html/html.worker.js",typescript:"monaco-editor/esm/vs/language/typescript/ts.worker.js",javascript:"monaco-editor/esm/vs/language/typescript/ts.worker.js"}[m]??"monaco-editor/esm/vs/editor/editor.worker.js";try{const T=new URL(b,import.meta.url).toString(),s=new Blob([`importScripts('${T}')`],{type:"application/javascript"});return URL.createObjectURL(s)}catch{return"https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/esm/vs/editor/editor.worker.js"}}};t.register({id:"yaml"});const l={topLevel:["id","info","set","rules","expression"],infoFields:["name","author","severity","description","tags","created","reference"],severity:["critical","high","medium","low","info"],requestFields:["method","path","headers","body","follow_redirects"],httpMethods:["GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"],requestVars:["request.url","request.url.host","request.url.path","request.url.query"],responseVars:["response.status","response.body","response.headers","response.content_type","response.raw_header","response.latency"],builtins:["BaseURL","Hostname","oob","oob.HTTP","oob.DNS","oob.ProtocolHTTP","oob.ProtocolDNS"],operators:["&&","||","!","==","!=",">","<",">=","<="],functions:["response.body.bcontains","response.body.contains","response.body.icontains","response.body.matches","response.body.bmatches","response.headers.contains","response.headers.icontains","response.raw_header.bcontains","response.raw_header.ibcontains"],aliases:[{label:"status",target:"response.status"},{label:"headers",target:"response.headers"},{label:"body",target:"response.body"},{label:"url",target:"request.url"},{label:"get",target:"GET"},{label:"post",target:"POST"},{label:"put",target:"PUT"},{label:"delete",target:"DELETE"},{label:"head",target:"HEAD"},{label:"options",target:"OPTIONS"},{label:"patch",target:"PATCH"}],commonFunctions:["contains","icontains","bcontains","ibcontains","startsWith","bstartsWith","endsWith","matches","bmatches","submatch","bsubmatch","md5","base64","base64Decode","urlencode","urldecode","toUpper","toLower","substr","replaceAll","printable","toUintString","hexdecode","faviconHash","randomInt","randomLowercase","sleep","year","shortyear","month","day","timestamp_second","versionCompare","ysoserial","aesCBC","repeat","decimal","length","oobCheck","wait","jndi"],setFunctions:["md5","base64","base64Decode","urlencode","urldecode","toUpper","toLower","substr","replaceAll","printable","toUintString","hexdecode","faviconHash","randomInt","randomLowercase","sleep","year","shortyear","month","day","timestamp_second","versionCompare","ysoserial","aesCBC","repeat","decimal","length","jndi"]},U=d=>l.topLevel.includes(d)?t.CompletionItemKind.Struct:l.infoFields.includes(d)?t.CompletionItemKind.Field:l.httpMethods.includes(d)?t.CompletionItemKind.Enum:l.severity.includes(d)?t.CompletionItemKind.Enum:l.builtins.includes(d)||l.requestVars.includes(d)||l.responseVars.includes(d)?t.CompletionItemKind.Variable:l.operators.includes(d)?t.CompletionItemKind.Operator:l.functions.includes(d)||l.commonFunctions.includes(d)||d.includes("contains")||d.includes("matches")?t.CompletionItemKind.Function:t.CompletionItemKind.Keyword;t.setMonarchTokensProvider("yaml",{tokenizer:{root:[[/#.*$/,"comment"],[/\b(id|info|set|rules|expression|name|author|severity|description|tags|created|reference|request|response|method|path|headers|body|follow_redirects)\s*:/,"key"],[/\b(critical|high|medium|low|info|GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b/,"value"],[/\b(request\.url|request\.url\.host|request\.url\.path|request\.url\.query|response\.status|response\.body|response\.headers|response\.content_type|response\.body\.bcontains|response\.body\.contains|response\.body\.icontains|response\.body\.matches|response\.body\.bmatches|response\.headers\.contains|response\.headers\.icontains|BaseURL|Hostname)\b/,"value"],[/&&|\|\||==|!=|>=|<=|>|</,"operator.logic"],[/"([^"\\]|\\.)*"/,"value"],[/'([^'\\]|\\.)*'/,"value"],[/"([^"\\]|\\.)*$/,"value.invalid"],[/'([^'\\]|\\.)*$/,"value.invalid"],[/"/,"value","@string_double"],[/'/,"value","@string_single"],[/\d+\.\d+([eE][+-]?\d+)?/,"value"],[/\d+/,"value"],[/\b(true|false|null)\b/,"value"],[/^[a-zA-Z_][\w-]*\s*:/,"key"],[/\s+[a-zA-Z_][\w-]*\s*:/,"key"],[/^\s*-\s*/,"operator"],[/[|>][-+]?/,"operator"],[/^---\s*$/,"operator"],[/^\.\.\.\s*$/,"operator"],[/\s+/,"white"],[/./,"text"]],string_double:[[/[^\\"]+/,"value"],[/\\./,"value.escape"],[/"/,"value","@pop"]],string_single:[[/[^\\']+/,"value"],[/\\./,"value.escape"],[/'/,"value","@pop"]]}});t.registerCompletionItemProvider("yaml",{triggerCharacters:Array.from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:"),provideCompletionItems:(d,m)=>{const y=d.getWordUntilPosition(m),b=d.getLineContent(m.lineNumber),T=b.substring(0,m.column-1),s={startLineNumber:m.lineNumber,endLineNumber:m.lineNumber,startColumn:y.startColumn,endColumn:y.endColumn},x=e=>e.match(/^(\s*)/)?.[1].length??0,K=e=>e.match(/^\s*([A-Za-z_][\w-]*)\s*:/)?.[1],c=(()=>{const e=[],i=x(b);for(let o=m.lineNumber;o>=Math.max(1,m.lineNumber-80);o--){const a=d.getLineContent(o),n=K(a);if(!n)continue;const p=x(a);p<i&&e.push({indent:p,key:n})}return e.sort((o,a)=>o.indent-a.indent),e.map(o=>o.key)})(),f=b.match(/^\s*([A-Za-z_][\w-]*)\s*:/)?.[1]??void 0,C=/:/.test(b),u=!C||/^\s*[-]?\s*[A-Za-z_][\w-]*$/.test(T.trim()),g=x(b)===0,P=c.includes("info"),$=c.includes("rules"),E=f==="expression"||$&&c[c.length-1]==="expression",I=c.includes("set"),R=c.includes("headers"),A=c.includes("request"),r=[];if(I&&u&&r.push({label:"rboundary: randomLowercase(8)",kind:t.CompletionItemKind.Snippet,insertText:"rboundary: randomLowercase(8)",insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"文件上传用的 multipart/form-data 边界变量",filterText:"rboundary",sortText:"09_set_rboundary",detail:"片段",range:s}),R&&u&&(r.push({label:"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}",kind:t.CompletionItemKind.Snippet,insertText:"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}",insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"用于文件上传的 multipart/form-data（引用 set 中的 rboundary）",filterText:"Content-Type",sortText:"10_headers_content_type_multipart",detail:"片段",range:s}),r.push({label:"Content-Type: application/json",kind:t.CompletionItemKind.Snippet,insertText:"Content-Type: application/json",insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"JSON 请求的内容类型",filterText:"Content-Type",sortText:"10_headers_content_type_json",detail:"片段",range:s}),r.push({label:"Content-Type: application/xml",kind:t.CompletionItemKind.Snippet,insertText:"Content-Type: application/xml",insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"XML 请求的内容类型",filterText:"Content-Type",sortText:"10_headers_content_type_xml",detail:"片段",range:s}),r.push({label:"Authorization: Basic YWRtaW46",kind:t.CompletionItemKind.Snippet,insertText:"Authorization: Basic YWRtaW46",insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"Basic 认证（admin:）示例",filterText:"Authorization",sortText:"10_headers_authorization_basic",detail:"片段",range:s}),r.push({label:"Cookie: redirect",kind:t.CompletionItemKind.Snippet,insertText:"Cookie: redirect",insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"简单 Cookie 示例",filterText:"Cookie",sortText:"10_headers_cookie_redirect",detail:"片段",range:s}),r.push({label:"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}",kind:t.CompletionItemKind.Snippet,insertText:"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}",insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"用于文件上传的 multipart/form-data（引用 set 中的 rboundary）",filterText:"Content-Type",sortText:"10_headers_content_type_multipart",detail:"片段",range:s})),A&&u&&r.push({label:"body: | (multipart/form-data 上传体)",kind:t.CompletionItemKind.Snippet,insertText:`body: |
	------WebKitFormBoundary{{rboundary}}
	Content-Disposition: form-data; name="file"; filename="xx123.txt"
	Content-Type: image/jpeg

	{{randstr}}
	------WebKitFormBoundary{{rboundary}}--`,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"文件上传请求体（使用 set:rboundary、urldecodePayload 和 randstr）",filterText:"body",sortText:"11_request_body_multipart",detail:"片段",range:s}),$&&u){const e=v.find(i=>i.label==="extractors (regex)");e&&r.push({label:e.label,kind:t.CompletionItemKind.Snippet,insertText:e.insertText,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:e.documentation??"片段：提取器",filterText:"extractors",sortText:e.sortText??`08_extractors_${e.label}`,detail:"片段",range:s})}if(g&&u){const e=v.find(W=>W.label==="extractors (word)");e&&r.push({label:e.label,kind:t.CompletionItemKind.Snippet,insertText:e.insertText,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:e.documentation??"片段：提取器",filterText:"extractors",sortText:e.sortText??`08_extractors_${e.label}`,detail:"片段",range:s});const i=" ".repeat(x(b)),o=i+"  ",a=o+"  ",n=a+"  ",p=n+"  ",S=new Date().toISOString().split("T")[0].replace(/-/g,"/"),F=`${i}set:
${o}rboundary: randomLowercase(8)
${o}randfilename: randomLowercase(6)
${o}randbody: randomLowercase(32)
${i}rules:
${o}r0:
${a}request:
${n}method: POST
${n}path: /test/upload.do
${n}headers:
${p}Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}
${n}body: |
${p}------WebKitFormBoundary{{rboundary}}
${p}Content-Disposition: form-data; name="file"; filename="{{randfilename}}.txt"
${p}Content-Type: image/jpeg
${p}
${p}{{randbody}}
${p}------WebKitFormBoundary{{rboundary}}--
${a}expression: response.status == 200
${o}r1:
${a}request:
${n}method: GET
${n}path: /test/{{randfilename}}.txt
${a}expression: response.status == 200 && response.body.bcontains(bytes(randbody))
${i}expression: r0() && r1()`;r.push({label:"rules:（文件上传模版 · multipart/form-data）",kind:t.CompletionItemKind.Snippet,insertText:F,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"一次性插入 set / rules(r0:POST上传, r1:GET校验) / 最终 expression 的完整模版",filterText:"rules",sortText:"01_rules_upload_template",detail:"片段",range:s});const L=`${i}rules:
${o}r0:
${a}request:
${n}method: GET
${n}path: /home
${a}expression: response.status == 200 && response.body.bcontains(b'home')
${i}expression: r0()`;r.push({label:"rules:（通用 GET 模版）",kind:t.CompletionItemKind.Snippet,insertText:L,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:'最常见的 GET 检测模版：访问 /home 并校验 body 是否包含 "home"',filterText:"rules",sortText:"00_rules_simple_get_template",detail:"片段",range:s});const q=`${i}rules:
${o}r0:
${a}request:
${n}method: POST
${n}path: /login
${n}body: "username=admin&password=123456"
${a}expression: response.status == 200 && response.body.bcontains(b'login')
${i}expression: r0()`;r.push({label:"rules:（通用 POST 模版）",kind:t.CompletionItemKind.Snippet,insertText:q,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:'通用 POST 检测模版：提交 /login 并校验 body 是否包含 "login"',filterText:"rules",sortText:"00_rules_simple_post_template",detail:"片段",range:s});const D=`${i}set:
${o}oob: oob()
${o}oobHTTP: oob.HTTP
${i}rules:
${o}r0:
${a}request:
${n}method: POST
${n}path: /test
${n}headers:
${p}Content-Type: application/json
${n}body: |
${p}{"mtu":"; curl {{oobHTTP}};","data":"hi"}
${a}expression: oobCheck(oob, oob.ProtocolHTTP, 3)
${i}expression: r0()`;r.push({label:"rules:（oob HTTP 模版）",kind:t.CompletionItemKind.Snippet,insertText:D,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"OOB HTTP 检测：在 JSON 体中触发 curl 到 oobHTTP，并使用 oobCheck 进行回显校验",filterText:"rules",sortText:"00_rules_oob_http_template",detail:"片段",range:s});const B=i+`set:
`+o+`oob: oob()
`+o+`oobDNS: oob.DNS
`+i+`rules:
`+o+`r0:
`+a+`request:
`+n+`method: GET
`+n+"path: /cmd=`ping {{oobDNS}}`\n"+a+`expression: oobCheck(oob, oob.ProtocolDNS, 3)
`+i+"expression: r0()";r.push({label:"rules:（oob DNS 模版）",kind:t.CompletionItemKind.Snippet,insertText:B,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"OOB DNS 检测：通过 ping 触发到 oobDNS，并使用 oobCheck 进行回显校验",filterText:"rules",sortText:"00_rules_oob_dns_template",detail:"片段",range:s});const O=`${i}rules:
${o}r0:
${a}request:
${n}method: GET
${n}path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(10)))a)--+
${a}expression: |
${n}response.status == 200 &&
${n}response.body.bcontains(b'created_at') &&
${n}response.body.bcontains(b'video_id') &&
${n}response.latency <= 12000 &&  
${n}response.latency >= 10000
${o}r1:
${a}request:
${n}method: GET
${n}path: /?rest_route=/h5vp/v1/view/1&id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+
${a}expression: |
${n}response.status == 200 &&
${n}response.body.bcontains(b'created_at') &&
${n}response.body.bcontains(b'video_id') &&
${n}response.latency <= 8000 &&  
${n}response.latency >= 6000

${i}extractors:
${o}- type: word
${a}extractor:
${n}latency1: "6s"
${n}latency2: "10s"
${i}expression: r0() && r1()`;r.push({label:"rules:（SQL盲注 模版）",kind:t.CompletionItemKind.Snippet,insertText:O,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"基于 SLEEP 延时的 SQL 盲注检测：两次请求分别触发 10s/6s 并用 latency 验证",filterText:"rules",sortText:"00_rules_sql_blind_template",detail:"片段",range:s});const H=i+`id: CVE-2001-1473

`+i+`info:
`+o+`name: Deprecated SSHv1 Protocol Detection
`+o+`author: demo
`+o+`severity: high
`+o+`verified: true
`+o+`description: SSHv1 is deprecated and has known cryptographic issues.
`+o+`affected: ssh-1
`+o+`solutions: Upgrade to SSH-2 or later.
`+o+`reference:
`+a+`- https://www.kb.cert.org/vuls/id/684820
`+a+`- https://nvd.nist.gov/vuln/detail/CVE-2001-1473
`+o+`tags: cve,cve2001,network,ssh,openssh
`+o+`created: ${S}`;r.push({label:"info:（完整模版）",kind:t.CompletionItemKind.Snippet,insertText:H,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"插入完整 info 区块及 id（包含 reference 列表、tags、created 等）",filterText:"info",sortText:"00_info_full_template",detail:"片段",range:s});const N=`${i}info:
${o}name: MySQL Dectect
${o}author: zan8in
${o}severity: high
${o}verified: true
${o}description: |-
${a}MySQL instance was detected
${o}tags: network,db,mysql
${o}created: ${S}`;r.push({label:"info:（精简模版）",kind:t.CompletionItemKind.Snippet,insertText:N,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"插入简化 info 区块（含 description、tags、created）",filterText:"info",sortText:"01_info_simple_template",detail:"片段",range:s});const j=`${i}set:
${o}hostname: request.url.host
${o}host: request.url.domain
${i}rules:
${o}r0:
${a}request:
${n}type: tcp
${n}host: "{{hostname}}"
${n}data: "\\n"
${n}read-size: 1024
${a}expression: response.raw.bcontains(b'No such') && response.raw.bcontains(b'lstat() failed')
${o}r1:
${a}request:
${n}type: tcp
${n}host: "{{host}}:3306"
${n}data: "\\n"
${n}read-size: 1024
${a}expression: response.raw.bcontains(b'No such') && response.raw.bcontains(b'lstat() failed')
${i}expression: r0() || r1()`;r.push({label:"rules:（TCP 模版）",kind:t.CompletionItemKind.Snippet,insertText:j,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"TCP 探测模版：分别对目标与 3306 进行 TCP 探测并用原始响应字节判断",filterText:"rules",sortText:"00_rules_tcp_template",detail:"片段",range:s})}if(I&&C&&!u){for(const e of l.setFunctions){const i=h[e]??`${e}(\${1})`;r.push({label:`${e}(... )`,kind:t.CompletionItemKind.Function,insertText:i,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"Afrog 函数（set 值位置）",filterText:e,sortText:`26_setfunc_${e}`,detail:"片段",range:s})}r.push({label:'base64(bytes("..."))',kind:t.CompletionItemKind.Function,insertText:h["base64(bytes)"],insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"嵌套 bytes 的 Base64",filterText:"base64(bytes",sortText:"26_setfunc_base64_bytes",detail:"片段",range:s}),r.push({label:'shortyear(0) + "_" + month(0) + "_" + day(0) + ".log"',kind:t.CompletionItemKind.Text,insertText:h["logfile-template"],insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"日志文件名模板",filterText:"logfile",sortText:"27_set_logfile_template",detail:"片段",range:s});for(const e of["oob.HTTP","oob.DNS"])r.push({label:e,kind:t.CompletionItemKind.Constant,insertText:e,documentation:"OOB 常量",filterText:e,sortText:`27_set_oob_${e}`,detail:"常量",range:s});r.push({label:"oob()",kind:t.CompletionItemKind.Function,insertText:h.oob,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:"创建 OOB 句柄",filterText:"oob(",sortText:"27_set_oob_handle",detail:"片段",range:s})}if(u&&g)for(const e of l.topLevel)r.push({label:e,kind:U(e),insertText:e,documentation:`Afrog POC 顶级键: ${e}`,filterText:e,sortText:`10_${e}`,detail:"顶级键",range:s});if(u&&$)for(const e of["request","response","expression"])r.push({label:e,kind:t.CompletionItemKind.Property,insertText:e,documentation:`rules 子键: ${e}`,filterText:e,sortText:`14_${e}`,detail:"rules 子键",range:s});if(u&&P)for(const e of l.infoFields)r.push({label:e,kind:t.CompletionItemKind.Field,insertText:e,documentation:`info 字段: ${e}`,filterText:e,sortText:`12_${e}`,detail:"info 字段",range:s});if(f==="severity")for(const e of l.severity)r.push({label:e,kind:t.CompletionItemKind.Enum,insertText:e,documentation:"枚举：严重级别",filterText:e,sortText:`20_${e}`,detail:"枚举：严重级别",range:s});if(f==="method"){for(const e of l.httpMethods)r.push({label:e,kind:t.CompletionItemKind.Enum,insertText:e,documentation:"HTTP 方法",filterText:e,sortText:`21_${e}`,detail:"枚举：HTTP 方法",range:s});for(const e of l.aliases.filter(i=>["GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"].includes(i.target)))r.push({label:e.label,kind:t.CompletionItemKind.Enum,insertText:e.target,documentation:`HTTP 方法别名 -> ${e.target}`,filterText:e.label,sortText:`21_alias_${e.label}`,detail:"HTTP 方法（别名）",range:s})}if(E){for(const e of l.operators)r.push({label:e,kind:t.CompletionItemKind.Operator,insertText:e,documentation:"运算符",filterText:e,sortText:`30_${e}`,detail:"运算符",range:s});for(const e of[...l.responseVars,...l.requestVars,...l.builtins])r.push({label:e,kind:t.CompletionItemKind.Variable,insertText:e,documentation:"内置变量",filterText:e,sortText:`25_${e}`,detail:"内置变量",range:s});for(const e of[...l.functions,...l.commonFunctions])r.push({label:e,kind:t.CompletionItemKind.Function,insertText:e,documentation:"内置/扩展函数",filterText:e,sortText:`26_${e}`,detail:"函数",range:s});for(const e of l.aliases)r.push({label:e.label,kind:t.CompletionItemKind.Variable,insertText:e.target,documentation:`别名 -> ${e.target}`,filterText:e.label,sortText:`24_${e.label}`,detail:`别名：${e.target}`,range:s});for(const e of z)r.push({label:e.label,kind:e.kind??t.CompletionItemKind.Function,insertText:e.insertText,insertTextRules:t.CompletionItemInsertTextRule.InsertAsSnippet,documentation:e.documentation??"表达式片段",filterText:e.label,sortText:e.sortText??`28_expr_${e.label}`,detail:"片段",range:s})}if(u&&c.includes("request"))for(const e of l.requestFields)r.push({label:e,kind:t.CompletionItemKind.Property,insertText:e,documentation:`request 字段: ${e}`,filterText:e,sortText:`15_${e}`,detail:"request 字段",range:s});if(u&&c.includes("response"))for(const e of["headers","body","content_type"])r.push({label:e,kind:t.CompletionItemKind.Property,insertText:e,documentation:`response 字段: ${e}`,filterText:e,sortText:`15_${e}`,detail:"response 字段",range:s});const k=[],_=new Set;for(const e of r){const i=`${e.label}|${e.kind}|${e.insertText}`;_.has(i)||(_.add(i),k.push(e))}return{suggestions:k}}});w.defineTheme("yaml-dark",{base:"vs-dark",inherit:!0,rules:[{token:"comment",foreground:"6A9955"},{token:"key",foreground:"569CD6"},{token:"keyword.afrog",foreground:"569CD6"},{token:"keyword.info",foreground:"569CD6"},{token:"keyword.rule",foreground:"569CD6"},{token:"keyword.request",foreground:"569CD6"},{token:"string",foreground:"B5CEA8"},{token:"number",foreground:"B5CEA8"},{token:"keyword",foreground:"B5CEA8"},{token:"keyword.severity",foreground:"B5CEA8"},{token:"keyword.method",foreground:"B5CEA8"},{token:"variable.builtin",foreground:"B5CEA8"},{token:"function.builtin",foreground:"B5CEA8"},{token:"variable.global",foreground:"B5CEA8"},{token:"operator",foreground:"D4D4D4"},{token:"operator.logic",foreground:"D4D4D4"}],colors:{}});w.defineTheme("yaml-light",{base:"vs",inherit:!0,rules:[{token:"comment",foreground:"008000"},{token:"key",foreground:"0000FF"},{token:"keyword.afrog",foreground:"0000FF"},{token:"keyword.info",foreground:"0000FF"},{token:"keyword.rule",foreground:"0000FF"},{token:"keyword.request",foreground:"0000FF"},{token:"string",foreground:"098658"},{token:"number",foreground:"098658"},{token:"keyword",foreground:"098658"},{token:"keyword.severity",foreground:"098658"},{token:"keyword.method",foreground:"098658"},{token:"variable.builtin",foreground:"098658"},{token:"function.builtin",foreground:"098658"},{token:"variable.global",foreground:"098658"},{token:"operator",foreground:"000000"},{token:"operator.logic",foreground:"000000"}],colors:{}});console.log("Monaco config loaded (AfrogSpec):",{hasMonaco:!!M,languagesRegistered:t?"yes":"no",yamlProviderRegistered:"yes",themesRegistered:"yes"});const h={randomInt:"randomInt(${1:10000}, ${2:99999})",randomLowercase:"randomLowercase(${1:6})",replaceAll:'replaceAll("${1:this is a test}", "${2:test}", "${3:Test}")',toUpper:'toUpper("${1:admin}")',toLower:'toLower("${1:Admin}")',md5:'md5("${1:123456}")',base64:'base64("${1:admin:admin}")',"base64(bytes)":'base64(bytes("${1:user:user}"))',base64Decode:'base64Decode("${1:YWRtaW46YWRtaW4=}")',urlencode:'urlencode(${1:base64("1234")})',urldecode:'urldecode("${1:https%3A%2F%2Fexample%2Ecom}")',year:"year(${1:0})",shortyear:"shortyear(${1:0})",month:"month(${1:0})",day:"day(${1:0})",timestamp_second:"timestamp_second(${1:0})",versionCompare:'versionCompare("${1:5.15.12}", "${2:<}", "${3:5.15.16}")',ysoserial:'ysoserial("${1:payload}", "${2:command}", ${3:encode})',aesCBC:'aesCBC("${1:text}", "${2:key}", "${3:iv}")',repeat:'repeat("${1:text}", ${2:count})',decimal:"decimal(${1:value})",length:"length(${1:value})",jndi:'jndi("${1:ldap://127.0.0.1/a}")',"logfile-template":'shortyear(${1:0}) + "_" + month(${2:0}) + "_" + day(${3:0}) + ".log"',oob:"oob()"},z=[{label:"response.body.bcontains(b'P')",insertText:"response.body.bcontains(b'${1:P}')",kind:t.CompletionItemKind.Function,documentation:"匹配响应体（字节）包含"},{label:"response.raw_header.bcontains(b'')",insertText:"response.raw_header.bcontains(b'${1:pattern}')",kind:t.CompletionItemKind.Function,documentation:"匹配原始响应头（字节）包含"},{label:"response.body.icontains(b'')",insertText:"response.body.icontains(b'${1:pattern}')",kind:t.CompletionItemKind.Function,documentation:"匹配响应体（字节）包含（不区分大小写）"},{label:"response.raw_header.ibcontains(b'')",insertText:"response.raw_header.ibcontains(b'${1:pattern}')",kind:t.CompletionItemKind.Function,documentation:"匹配原始响应头（字节）包含（不区分大小写）"},{label:'response.headers["content-type"].icontains("")',insertText:'response.headers["content-type"].icontains("${1:application/json}")',kind:t.CompletionItemKind.Function,documentation:"响应头 content-type 包含（不区分大小写）"},{label:'response.headers["location"].icontains("")',insertText:'response.headers["location"].icontains("${1:/redirect}")',kind:t.CompletionItemKind.Function,documentation:"响应头 location 包含（不区分大小写）"},{label:'"Set-Cookie: (?P<cookie>.+)".bsubmatch(response.raw_header)',insertText:'"Set-Cookie: (?P<cookie>.+)".bsubmatch(response.raw_header)',kind:t.CompletionItemKind.Function,documentation:"在原始响应头中进行字节子匹配（命名分组）"},{label:'"root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)',insertText:'"root:.*?:[0-9]*:[0-9]*:".bmatches(response.body)',kind:t.CompletionItemKind.Function,documentation:"在响应体中进行字节正则匹配"},{label:"response.latency <= 12000",insertText:"response.latency <= ${1:12000}",kind:t.CompletionItemKind.Operator,documentation:"响应延迟比较（毫秒）"},{label:"oobCheck(oob, oob.ProtocolHTTP, 3)",insertText:"oobCheck(${1:oob}, oob.ProtocolHTTP, ${2:3})",kind:t.CompletionItemKind.Function,documentation:"OOB 检测（HTTP）"},{label:"oobCheck(oob, oob.ProtocolDNS, 3)",insertText:"oobCheck(${1:oob}, oob.ProtocolDNS, ${2:3})",kind:t.CompletionItemKind.Function,documentation:"OOB 检测（DNS）"},{label:"ysoserial(payload, command, encode)",insertText:"ysoserial(${1:payload}, ${2:command}, ${3:encode})",kind:t.CompletionItemKind.Function,documentation:"反序列化利用载荷"},{label:"aesCBC(text,key,iv)",insertText:"aesCBC(${1:text}, ${2:key}, ${3:iv})",kind:t.CompletionItemKind.Function,documentation:"AES-CBC 加密"}],v=[{label:"extractors (regex)",insertText:`extractors:
  - type: regex
    extractor:
      ext1: '"(?P<mysql>[0-9]\\.[0-9]{1,2}\\.[0-9]{1,2})".bsubmatch(response.raw)'
      mysql: ext1["mysql"]`,documentation:"正则提取 mysql 版本号（命名分组）",sortText:"08_extractors_regex"},{label:"extractors (word)",insertText:`extractors:
  - type: word
    extractor:
      user: 'root'
      pass: "123456"`,documentation:"简单词提取（用户名/密码）",sortText:"08_extractors_word"}];export{M as default};
