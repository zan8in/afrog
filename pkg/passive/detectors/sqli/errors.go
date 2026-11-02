package sqli

import (
	"strings"
)

// 本文件负责「报错型」注入检测：用破坏语法闭合的探针把数据库报错逼出来，
// 再从响应体里匹配各方言特有的报错特征。
//
// 为什么单开一层：报错型是成本最低、证据最直接的确认方式——两次请求即可定论，
// 而且证据是「数据库自己把报错信息吐了出来」，不依赖相似度推断。它还能覆盖布尔
// 差分覆盖不到的位置（如 LIMIT / ORDER BY 这类没法追加 AND 条件的上下文）：
// 只要闭合符被打破，数据库就会报错。

// maxDBErrorBodyScan 限制报错特征扫描的响应体长度。报错信息总在响应前部，
// 没必要在几百 KB 的正文上做匹配。
const maxDBErrorBodyScan = 16 << 10

// dbErrorMarker 是一条数据库报错特征。
type dbErrorMarker struct {
	dialect string
	marker  string
}

// dbErrorMarkers 是主流数据库在语法错误时暴露的专有特征（按小写比较）。
//
// 只收「数据库自己吐出来的」完整句子，绝不收 "error" / "sql" / "syntax" 这类泛词：
// 它们在正常页面里随处可见，一旦纳入，报错型检测就会退化成误报机器。
var dbErrorMarkers = []dbErrorMarker{
	// MySQL / MariaDB
	{dialect: "mysql", marker: "you have an error in your sql syntax"},
	{dialect: "mysql", marker: "check the manual that corresponds to your mysql server version"},
	{dialect: "mysql", marker: "check the manual that corresponds to your mariadb server version"},
	{dialect: "mysql", marker: "supplied argument is not a valid mysql"},
	{dialect: "mysql", marker: "mysql_fetch_array()"},
	{dialect: "mysql", marker: "mysql_num_rows()"},
	{dialect: "mysql", marker: "warning: mysql_"},

	// PostgreSQL
	{dialect: "postgresql", marker: "syntax error at or near"},
	{dialect: "postgresql", marker: "unterminated quoted string"},
	{dialect: "postgresql", marker: "invalid input syntax for type"},
	{dialect: "postgresql", marker: "pg_query()"},
	{dialect: "postgresql", marker: "pg_exec()"},

	// Microsoft SQL Server
	{dialect: "mssql", marker: "unclosed quotation mark after the character string"},
	{dialect: "mssql", marker: "incorrect syntax near"},
	{dialect: "mssql", marker: "microsoft ole db provider for sql server"},
	{dialect: "mssql", marker: "sqlserver jdbc driver"},
	{dialect: "mssql", marker: "system.data.sqlclient."},

	// Oracle
	{dialect: "oracle", marker: "ora-01756"},
	{dialect: "oracle", marker: "ora-00933"},
	{dialect: "oracle", marker: "ora-00921"},
	{dialect: "oracle", marker: "ora-01722"},
	{dialect: "oracle", marker: "quoted string not properly terminated"},

	// SQLite
	{dialect: "sqlite", marker: "unrecognized token:"},
	{dialect: "sqlite", marker: "sqlite3::"},
	{dialect: "sqlite", marker: "sql logic error"},
	{dialect: "sqlite", marker: "sqlite_error"},

	// 补充的原生方言特征：数据库在框架下常只透出简短错误码或片段，
	// 拿不到上面那些完整句子时，这些也能定论。
	{dialect: "mssql", marker: "conversion failed when converting"},
	{dialect: "oracle", marker: "ora-00904"},
	{dialect: "oracle", marker: "ora-00936"},
	{dialect: "oracle", marker: "ora-00942"},
	{dialect: "postgresql", marker: "unterminated dollar-quoted string"},

	// ORM / 数据访问层 / 驱动层。
	//
	// 用框架（Hibernate、MyBatis、Django、SQLAlchemy、ActiveRecord 等）的站点通常
	// 不会把数据库原生报错原样吐出，而是抛一个框架异常，但异常消息里往往仍保留着
	// 数据库的语法错误文本。这类特征与原生报错同源，只是外面套了一层框架类名。
	// 只收「明确指向 SQL 语法 / 数据库异常」的类名与消息，框架的泛型异常
	// （空指针、类型错误等）一律不收，否则任意错误页都会被当成注入。
	//
	// JVM：JDBC / Hibernate / MyBatis
	{dialect: "jdbc", marker: "java.sql.sqlsyntaxerrorexception"},
	{dialect: "jdbc", marker: "java.sql.sqlexception"},
	{dialect: "jdbc", marker: "org.postgresql.util.psqlexception"},
	{dialect: "hibernate", marker: "org.hibernate.exception.sqlgrammarexception"},
	{dialect: "hibernate", marker: "org.hibernate.exception.sqlexception"},
	{dialect: "hibernate", marker: "could not extract resultset"},
	{dialect: "hibernate", marker: "unexpected end of subtree"},
	{dialect: "mybatis", marker: "org.apache.ibatis.exceptions.persistenceexception"},
	{dialect: "mybatis", marker: "mybatis system exception"},
	{dialect: "spring", marker: "bad sql grammar"},

	// .NET：SqlClient / OleDb / SQLite
	{dialect: "aspnet", marker: "system.data.sqlclient.sqlexception"},
	{dialect: "aspnet", marker: "system.data.oledb.oledbexception"},
	{dialect: "aspnet", marker: "system.data.sqlite.sqliteexception"},

	// PHP：PDO / mysqli
	{dialect: "php", marker: "pdoexception"},
	{dialect: "php", marker: "sqlstate["},
	{dialect: "php", marker: "mysqli_sql_exception"},

	// Python：Django / SQLAlchemy / 各驱动
	{dialect: "django", marker: "django.db.utils."},
	{dialect: "django", marker: "django.db.backends."},
	{dialect: "sqlalchemy", marker: "sqlalchemy.exc."},
	{dialect: "python", marker: "psycopg2.errors."},
	{dialect: "python", marker: "pymysql.err."},
	{dialect: "python", marker: "sqlite3.operationalerror"},

	// Ruby on Rails
	{dialect: "rails", marker: "activerecord::statementinvalid"},
	{dialect: "rails", marker: "pg::syntaxerror"},
	{dialect: "rails", marker: "mysql2::error"},

	// Node.js
	{dialect: "node", marker: "sequelizedatabaseerror"},
	{dialect: "node", marker: "er_parse_error"},
	{dialect: "node", marker: "sqlite3error"},
}

// errorProbe 是一个破坏语法闭合的探针。
type errorProbe struct {
	// name 说明破坏方式。
	name string
	// tmpl 中的 %s 为原始参数值。
	tmpl string
}

// errorProbes 只做「补一个多余的闭合符」，按命中概率从高到低排列。
//
// 刻意不发完整的注入表达式：报错型只要让语法不成立就够了，多带条件既更容易被
// WAF 拦下，也会让证据变得难以解释。
var errorProbes = []errorProbe{
	{name: "单引号", tmpl: "%s'"},
	{name: "双引号", tmpl: `%s"`},
	{name: "括号", tmpl: "%s)"},
	{name: "括号加引号", tmpl: "%s')"},
	// 反斜杠：假设应用对引号做了 addslashes 式转义、却漏掉了反斜杠本身，补一个
	// 反斜杠会让应用补上的闭合引号被转义掉，字符串永不闭合 → 报错。这种形态用
	// 布尔差分构造不出来（条件会被吞进字符串里），只能靠报错触发。
	{name: "反斜杠", tmpl: `%s\`},
}

// headerErrorProbes 是「只有头部注入点」的轻量档使用的探针。
//
// 只保留破坏面最广、命中率最高的单引号一条，把每个头部注入点的成本钉死在最多
// 两次请求——请求头几乎每个请求都带，成本必须是有界的。
var headerErrorProbes = errorProbes[:1]

// reportError 在响应体里匹配数据库报错特征，返回命中的方言与特征词。
func reportError(body []byte) (string, string) {
	low := lowerBodyPrefix(body, maxDBErrorBodyScan)
	if low == "" {
		return "", ""
	}
	for _, m := range dbErrorMarkers {
		if strings.Contains(low, m.marker) {
			return m.dialect, m.marker
		}
	}
	return "", ""
}

// containsMarker 判断响应体是否本来就含某条特征。
//
// 这是报错型的反向闸门：站点自带的文案（如一篇讲 SQL 报错的文章）里出现特征词，
// 与「我们打出了报错」是两回事，基线里已有的特征一律不采信。
func containsMarker(body []byte, marker string) bool {
	if marker == "" {
		return false
	}
	return strings.Contains(lowerBodyPrefix(body, maxDBErrorBodyScan), marker)
}

// lowerBodyPrefix 截取响应体前 limit 字节并折成小写。
//
// 先截断再折小写：ToLower 会复制整串，超大响应体上先折小写等于白白分配一份内存。
// 按字节截断可能切断一个多字节字符，但匹配目标全是 ASCII 特征，切在半路无影响。
func lowerBodyPrefix(body []byte, limit int) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > limit {
		body = body[:limit]
	}
	return strings.ToLower(string(body))
}
