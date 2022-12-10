package targetlive

import (
	"strings"
	"sync"
	"sync/atomic"
)

var TLive *TargetLive

type TargetLive struct {
	live        sync.Map
	nolive      sync.Map
	max         int
	noliveCount uint32
	noliveSlice []string
	mutex       *sync.Mutex
	rtMutex     *sync.Mutex
	white       []string
	black       []string
}

type RequestTarget struct {
	t string
	v int
}

func New(maxSize int) {
	TLive = &TargetLive{live: sync.Map{}, nolive: sync.Map{}, max: maxSize, noliveSlice: []string{}, mutex: &sync.Mutex{}, white: []string{}, black: []string{}, rtMutex: &sync.Mutex{}}
}

func (tl *TargetLive) AddRequestTarget(t string, v int) {
	tl.rtMutex.Lock()
	if v == 1 {
		tl.white = append(tl.white, t)
	}
	if v == 2 {
		tl.black = append(tl.black, t)
	}
	tl.rtMutex.Unlock()
}

func (tl *TargetLive) ListRequestTargets() []string {
	r := []string{}
	for _, t := range tl.white {
		rb := false
		for _, b := range tl.black {
			if b == t {
				rb = true
				break
			}
		}
		if !rb {
			r = append(r, t)
		}
	}
	return r
}

// Target 存活处理函数
// target 待验证得 target
// live 如果 target 请求返回状态码小于 500 的话 live = 1
// 如果参数 live = 1 ，添加target到liveMap
// 如果参数 live = 0, 添加target到noliveMap
// 如果参数 live = -1, 判断 target 状态，live返回1，nolive返回-1（黑名单），未确定live/nolive的返回 2
func (tl *TargetLive) HandleTargetLive(target string, live int) int {
	target = strings.TrimSpace(target)

	if live == 1 {
		// TODO: handle live
		_, ok := tl.live.Load(target)
		if !ok {
			tl.live.Store(target, 0)
		}
		return 0
	}

	if live == 0 {
		// TODO: handle nolive
		c, b := tl.nolive.Load(target)
		if b && c.(int) >= tl.max {
			atomic.AddUint32(&tl.noliveCount, 1)
			tl.appendNoliveSlices(target)
			return 0
		}
		if b {
			tl.nolive.Store(target, c.(int)+1)
			if c.(int)+1 >= tl.max {
				atomic.AddUint32(&tl.noliveCount, 1)
				tl.appendNoliveSlices(target)
			}
			// fmt.Println("tl.nolive.Store(target, c.(int)+1)", target, c.(int)+1)
			return 0
		}
		tl.nolive.Store(target, 1)
		// fmt.Println("tl.nolive.Store(target, 1)", target, 1)
		return 0
	}

	if live == -1 {
		// TODO: handle checkLive
		_, ok := tl.live.Load(target)
		if ok {
			return 1
		}
		v, ok := tl.nolive.Load(target)
		if ok && v.(int) >= tl.max {
			// fmt.Println(">>>>>", target, ok, v.(int), tl.max, v.(int) >= tl.max, len(tl.noliveSlice))
			return -1
		}
	}

	return 2
}

func (tl *TargetLive) Reset(target string) {
}

func (tl *TargetLive) appendNoliveSlices(t string) {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()
	if len(tl.noliveSlice) == 0 {
		tl.noliveSlice = append(tl.noliveSlice, t)
		return
	}
	for _, v := range tl.noliveSlice {
		if v == t {
			return
		}
	}
	tl.noliveSlice = append(tl.noliveSlice, t)
}

func (tl *TargetLive) GetNoLiveCount() int {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()
	return len(tl.noliveSlice)
}

func (tl *TargetLive) GetNoLiveSlice() []string {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()
	return tl.noliveSlice
}

func (tl *TargetLive) GetNoLiveAtomicCount() uint32 {
	return tl.noliveCount
}

func (tl *TargetLive) IsNoLiveAtomic(target string) bool {
	if tl.HandleTargetLive(target, -1) == -1 {
		return true
	}
	return false
}
