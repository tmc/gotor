// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"

	_ "net/http/pprof"
)

import _ "expvar"

func main() {
	SetupRand()
	SeedCellBuf()

	torConfig := Config{
		IsPublicServer:    true,
		Platform:          "Tor 0.2.6.2-alpha on Go",
		BandwidthAvg:      1073741824,
		BandwidthBurst:    1073741824,
		BandwidthObserved: 1 << 16,
		DataDirectory:     ".",
	}
	if err := torConfig.ReadFile(os.Args[1]); err != nil {
		log.Panicln(err)
	}

	or, err := NewOR(&torConfig)
	if err != nil {
		log.Panicln(err)
	}

	/*
		go func() {
			or.RequestCircuit(&CircuitRequest{
				localID: 5,
				connHint: ConnectionHint{
					address: [][]byte{[]byte{127,0,0,1,35,41}},
				},
			})
		}()
	*/

	anythingFinished := make(chan int)
	go func() {
		time.Sleep(time.Second * 5)
		or.Run()
		anythingFinished <- 1
	}()
	go func() {
		Log(LOG_WARN, "%v", http.ListenAndServe("localhost:6060", nil))
	}()

	log.Println("publishing")
	or.PublishDescriptor()
	log.Println("done publishing")

	nextRotate := time.After(time.Hour * 1)
	nextPublish := time.After(time.Hour * 18)
	time.Sleep(time.Second)
	for {
		select {
		case <-nextRotate: //XXX randomer intervals
			if err := or.RotateKeys(); err != nil {
				log.Println("got nextrotate", err)
				Log(LOG_WARN, "%v", errors.Wrap(err, "RotateKeys"))
			}
			nextRotate = time.After(time.Hour * 1)

		case <-nextPublish:
			log.Println("got nextPublish")
			or.PublishDescriptor()
			nextPublish = time.After(time.Hour * 18)

		case <-anythingFinished:
			log.Panicln("Somehow a main.go goroutine we spawned managed to finish, which is not good")
		}
	}
}
