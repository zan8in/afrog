package targets

import (
	"sync"
	"time"

	"github.com/panjf2000/ants"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/poc"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
)

func RunTargetLivenessCheck(options *config.Options) {
	first := true
	for {
		// fmt.Println("\r\nRunTargetLivenessCheck start", len(options.Targets), options.TargetLive.GetNoLiveAtomicCount())
		// reqCount := 0
		if len(options.Targets) > 0 {
			size := 100
			if options.Config.FingerprintSizeWaitGroup > 0 {
				size = int(options.Config.FingerprintSizeWaitGroup)
			}

			var wg sync.WaitGroup
			p, _ := ants.NewPoolWithFunc(size, func(wgTask any) {
				defer wg.Done()
				url := wgTask.(poc.WaitGroupTask).Value.(string)
				key := wgTask.(poc.WaitGroupTask).Key
				// 首次检测 target list
				if first && options.TargetLive.HandleTargetLive(url, -1) != -1 {
					url, statusCode := http2.CheckTargetHttps(url)
					// fmt.Println("once", url, statusCode)
					if statusCode == -1 || statusCode >= 500 {
						// url 加入 targetlive 黑名单 +1
						options.TargetLive.HandleTargetLive(url, 0)
					} else {
						options.TargetLive.HandleTargetLive(url, 1)
					}
					// reqCount += 1
				}
				// 非首次检测 target list
				if !first && options.TargetLive.HandleTargetLive(url, -1) == 2 {
					url, statusCode := http2.CheckTargetHttps(url)
					// fmt.Println(url, statusCode)
					if statusCode == -1 || statusCode >= 500 {
						// url 加入 targetlive 黑名单 +1
						options.TargetLive.HandleTargetLive(url, 0)
					} else {
						options.TargetLive.HandleTargetLive(url, 1)
					}
					// reqCount += 1
				}
				if options.Targets[key] != url {
					options.Targets[key] = url
				}
			})
			defer p.Release()

			for k, target := range options.Targets {
				wg.Add(1)
				_ = p.Invoke(poc.WaitGroupTask{Value: target, Key: k})
			}
			wg.Wait()
		}
		// fmt.Println("request count", reqCount)
		// reqCount = 0
		first = false
		time.Sleep(time.Second * 30)
		// fmt.Println("target noLive count: ", options.TargetLive.GetNoLiveCount(), options.TargetLive.GetNoLiveAtomicCount())
		// for _, target := range options.TargetLive.GetNoLiveSlice() {
		// 	fmt.Println("\r\nnolive target: ", target)
		// }
		// lt := options.TargetLive.ListRequestTargets()
		// if len(lt) > 0 {
		// 	for _, v := range lt {
		// 		fmt.Println("777777777777777", v, " 仍在请求中...")
		// 	}
		// }
		// fmt.Println("正在请求中....总数：", len(lt))
	}

}
