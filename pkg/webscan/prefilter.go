package webscan

// 正文类源的「多模式预筛器」。
//
// 背景：社区规则集有近八百条正文类模式（body/html/css/text），逐条对正文做
// strings.Index 预筛，成本是 O(规则数 × 正文长度)。实测 53KB 的真实页面要 120ms，
// 放大到 512KB 的上限就是秒级——放在被动扫描的门控池里会直接造成队首阻塞。
//
// 这里用一个 Aho–Corasick 自动机把所有字面量并成一次扫描：无论多少条模式，
// 通读正文只走一遍。语义完全等价——预筛只负责「字面量在不在」，
// 命中之后照旧跑那条模式自己的正则。

// acNode 是自动机的一个状态。
type acNode struct {
	// next 是字节到下一状态的转移。用 map 而非 256 宽数组：节点数上万，
	// 数组会吃掉数十 MB，而单个节点的出边通常只有个位数。
	next map[byte]int32
	// fail 是失配时的跳转状态。
	fail int32
	// out 是落到本状态的所有字面量 id（已合并后缀状态的输出）。
	out []int32
}

// literalIndex 是若干字面量的多模式匹配器。
type literalIndex struct {
	nodes []acNode
}

// buildLiteralIndex 用给定的字面量构造自动机。
//
// 返回的自动机与 literals 一一对应：扫描结果里第 i 位为真，表示 literals[i]
// 出现在被扫描的文本中。
func buildLiteralIndex(literals []string) *literalIndex {
	idx := &literalIndex{nodes: []acNode{{}}}
	// insert 把一条字面量插入字典树，末端记下它的序号。
	for id, lit := range literals {
		state := int32(0)
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			nxt, ok := idx.nodes[state].next[c]
			if !ok {
				idx.nodes = append(idx.nodes, acNode{})
				nxt = int32(len(idx.nodes) - 1)
				if idx.nodes[state].next == nil {
					idx.nodes[state].next = make(map[byte]int32, 4)
				}
				idx.nodes[state].next[c] = nxt
			}
			state = nxt
		}
		idx.nodes[state].out = append(idx.nodes[state].out, int32(id))
	}

	// 按层 BFS 建立失配指针，并把失配状态的输出并进来——
	// 这样扫描时只需看当前状态的 out，不必再沿 fail 链回溯。
	queue := make([]int32, 0, len(idx.nodes))
	for _, s := range idx.nodes[0].next {
		idx.nodes[s].fail = 0
		queue = append(queue, s)
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for c, next := range idx.nodes[cur].next {
			f := idx.nodes[cur].fail
			for f != 0 {
				if _, ok := idx.nodes[f].next[c]; ok {
					break
				}
				f = idx.nodes[f].fail
			}
			if t, ok := idx.nodes[f].next[c]; ok && t != next {
				idx.nodes[next].fail = t
			} else {
				idx.nodes[next].fail = 0
			}
			if f2 := idx.nodes[next].fail; len(idx.nodes[f2].out) > 0 {
				idx.nodes[next].out = append(idx.nodes[next].out, idx.nodes[f2].out...)
			}
			queue = append(queue, next)
		}
	}
	return idx
}

// scan 在 text 上跑一遍自动机，把命中的字面量序号写进 hits（长度需等于字面量个数）。
func (idx *literalIndex) scan(text string, hits []bool) {
	if idx == nil || len(idx.nodes) == 0 || text == "" {
		return
	}
	state := int32(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		for {
			if nxt, ok := idx.nodes[state].next[c]; ok {
				state = nxt
				break
			}
			if state == 0 {
				break
			}
			state = idx.nodes[state].fail
		}
		for _, id := range idx.nodes[state].out {
			hits[id] = true
		}
	}
}
