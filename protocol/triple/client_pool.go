/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package triple

import (
	"errors"
	"sync"
	"time"
)

import (
	tri "dubbo.apache.org/dubbo-go/v3/protocol/triple/triple_protocol"
)

type ClientPool interface {
	Get(timeout time.Duration) (*tri.Client, error)
	Put(client *tri.Client)
	Close()

	MaxSize() int
	Closed() bool
}

var (
	ErrTriClientPoolClosed         = errors.New("tri client pool is closed")
	ErrTriClientPoolTimeout        = errors.New("tri client pool get timeout")
	ErrTriClientPoolCloseWhenEmpty = errors.New("empty tri client pool close")
)

const (
	autoScalerPeriod        = 700 * time.Millisecond // autoScaler interval
	maxExpandPerCycle       = 16                     // maximum number of clients to expand per cycle
	lowIdleThresholdDivisor = 5                      // consider clients insufficient if idle < curSize/5
	highIdleStreakLimit     = 10                     // consecutive high idle count to trigger shrinking
)

type TriClientPool struct {
	clients     chan *tri.Client
	factory     func() *tri.Client
	mu          sync.Mutex
	maxSize     int
	curSize     int
	closed      bool
	getTimeouts int // recent timeout count, used to trigger expansion

	fallback *tri.Client
}

func NewTriClientPool(maxSize int, factory func() *tri.Client) *TriClientPool {
	pool := &TriClientPool{
		clients: make(chan *tri.Client, maxSize),
		factory: factory,
		maxSize: maxSize,
	}
	go pool.autoScaler()
	return pool
}

// TriClient Get method
// timeout means how long to wait for an available client.
// TriClientPool keeps a fallback client pointer. If Get() times out,
// and the pool cannot expand at that moment, the pool will return fallback.
// This ensures there is at least one usable client.
// Get tries a non-blocking receive first. If that fails, it tries to expand.
// If expansion is not allowed, it waits for a client up to timeout.
// After timeout, if still no client, Get() returns ErrTimeout with fallback.
func (p *TriClientPool) Get(timeout time.Duration) (*tri.Client, error) {
	select {
	case cli := <-p.clients:
		return cli, nil
	default:
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrTriClientPoolClosed
	}
	// try to expand
	if p.curSize < p.maxSize {
		p.curSize++
		p.mu.Unlock()
		cli := p.factory()
		return cli, nil
	}
	p.mu.Unlock()

	select {
	case cli, ok := <-p.clients:
		if !ok {
			return nil, ErrTriClientPoolClosed
		}
		return cli, nil
	case <-time.After(timeout):
		p.recordTimeout()
		p.mu.Lock()
		if p.fallback == nil {
			p.fallback = p.factory()
		}
		p.mu.Unlock()
		return p.fallback, ErrTriClientPoolTimeout
	}
}

// TriClient Put method
// Put tries to put a tri.Client back into the pool.
// If it fails, Put will drop the client and notify the pool.
// Dropping a client is part of shrinking.
func (p *TriClientPool) Put(c *tri.Client) {
	if c == nil {
		return
	}

	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return
	}

	select {
	case p.clients <- c:
	default:
		p.mu.Lock()
		p.curSize--
		p.mu.Unlock()
	}
}

// close removes all clients from the channel and then closes it.
func (p *TriClientPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true

	for len(p.clients) > 0 {
		<-p.clients
		p.curSize--
	}

	close(p.clients)
	p.mu.Unlock()
}

func (p *TriClientPool) MaxSize() int {
	return p.maxSize
}

func (p *TriClientPool) Closed() bool {
	return p.closed
}

// autoScaler is the main worker that adjusts pool size.
// It checks regularly whether pool should expand or shrink.
// If the timeout count is high, autoScaler tends to expand.
// If the idle client count is often high, autoScaler tends to shrink.
func (p *TriClientPool) autoScaler() {
	ticker := time.NewTicker(autoScalerPeriod)
	defer ticker.Stop()
	consecutiveHighIdle := 0

	for range ticker.C {
		if p.Closed() {
			return
		}

		p.mu.Lock()
		curSize := p.curSize
		idle := len(p.clients)
		timeouts := p.getTimeouts
		p.getTimeouts = 0
		p.mu.Unlock()

		needExpand := checkExpand(curSize, idle, timeouts)
		if needExpand != 0 {
			p.expand(needExpand)
			consecutiveHighIdle = 0
			continue
		}

		needShrink := checkShrink(curSize, idle, &consecutiveHighIdle)
		if needShrink != 0 {
			p.shrink(needShrink)
		}
	}
}

// expand creates n more clients
func (p *TriClientPool) expand(n int) {
	for i := 0; i < n; i++ {
		p.mu.Lock()
		if p.curSize >= p.maxSize {
			p.mu.Unlock()
			return
		}
		p.curSize++
		p.mu.Unlock()

		cli := p.factory()
		p.Put(cli)
	}
}

// shrink removes n clients
func (p *TriClientPool) shrink(n int) {
	for i := 0; i < n; i++ {
		select {
		case <-p.clients:
			p.mu.Lock()
			p.curSize--
			p.mu.Unlock()
		default:
			return
		}
	}
}

// record timeout count
func (p *TriClientPool) recordTimeout() {
	p.mu.Lock()
	p.getTimeouts++
	p.mu.Unlock()
}

// compute expansion size
// expansion size is based on timeout count: 2 ^ timeouts
// if idle clients are less than 1/lowIdleThresholdDivisor of total, treat as busy and expand slightly
func checkExpand(curSize, idle, timeouts int) int {
	if timeouts > 0 {
		expand := 1 << timeouts
		if expand > maxExpandPerCycle {
			expand = maxExpandPerCycle
		}
		return expand
	}

	if idle < curSize/lowIdleThresholdDivisor {
		return 1
	}

	return 0
}

// if more than 60% of clients are idle, increase highIdleStreak
// highIdleStreak records how often idle rate is high
// if highIdleStreak >= highIdleStreakLimit, shrink pool to 1/8
func checkShrink(curSize int, idle int, highIdleStreak *int) int {
	if idle > curSize*6/10 {
		*highIdleStreak++
		if *highIdleStreak >= highIdleStreakLimit {
			shrink := curSize / 8
			if shrink < 1 {
				shrink = 1
			}
			*highIdleStreak = 0
			return shrink
		}
		return 0
	}

	*highIdleStreak = 0
	return 0
}
