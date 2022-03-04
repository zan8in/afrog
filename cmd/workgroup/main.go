package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/remeh/sizedwaitgroup"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	// Typical use-case:
	// 50 queries must be executed as quick as possible
	// but without overloading the database, so only
	// 8 routines should be started concurrently.
	swg := sizedwaitgroup.New(8)
	for i := 0; i < 50; i++ {
		swg.Add()
		go func(i int) {
			defer swg.Done()
			query(i)
		}(i)
	}

	swg.Wait()
}

func query(i int) {
	fmt.Println(i)
	ms := i + 500 + rand.Intn(500)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}
