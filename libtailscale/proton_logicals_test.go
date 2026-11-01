// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProtonLogicalsFreshnessAndErrors(t *testing.T) {
	now := time.Unix(100, 0)
	c := protonLogicalsCache{now: func() time.Time { return now }}
	calls := 0
	fail := false
	wantErr := errors.New("offline")
	fetch := func() (*logicalsResp, error) {
		calls++
		if fail {
			return nil, wantErr
		}
		return &logicalsResp{LogicalServers: []logicalServer{{Load: calls}}}, nil
	}
	first, _ := c.get("account-a", fetch)
	now = now.Add(protonLogicalsTTL - time.Nanosecond)
	if got, err := c.get("account-a", fetch); err != nil || got != first || calls != 1 {
		t.Fatal("fresh metadata fetched again")
	}
	now = now.Add(time.Nanosecond)
	fail = true
	if got, err := c.get("account-a", fetch); !errors.Is(err, wantErr) || got != nil {
		t.Fatal("served expired metadata on failure")
	}
	fail = false
	if got, err := c.get("account-a", fetch); err != nil || got == first || calls != 3 {
		t.Fatal("cached failure or failed to refresh")
	}
	if _, err := c.get("account-b", fetch); err != nil || calls != 4 {
		t.Fatal("shared metadata across accounts")
	}
	c.invalidate()
	if _, err := c.get("account-b", fetch); err != nil || calls != 5 {
		t.Fatal("invalidation retained metadata")
	}
}

func TestProtonLogicalsConcurrentMiss(t *testing.T) {
	var c protonLogicalsCache
	var calls atomic.Int32
	start, release := make(chan struct{}), make(chan struct{})
	fetch := func() (*logicalsResp, error) {
		if calls.Add(1) == 1 {
			close(start)
		}
		<-release
		return &logicalsResp{LogicalServers: []logicalServer{{ID: "shared"}}}, nil
	}
	var wg sync.WaitGroup
	results := make([]*logicalsResp, 32)
	for i := range results {
		wg.Add(1)
		go func() { defer wg.Done(); results[i], _ = c.get("account", fetch) }()
	}
	<-start
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate fetches: %d", calls.Load())
	}
	for _, got := range results {
		if got != results[0] {
			t.Fatal("callers received different snapshots")
		}
	}
}

func TestProtonLogicalsRetiredRequestCannotRefill(t *testing.T) {
	for _, changeAccount := range []bool{false, true} {
		var c protonLogicalsCache
		start, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			c.get("account-a", func() (*logicalsResp, error) { close(start); <-release; return &logicalsResp{}, nil })
		}()
		<-start
		c.invalidate()
		scope := "account-a"
		if changeAccount {
			scope = "account-b"
		}
		fresh := &logicalsResp{}
		c.get(scope, func() (*logicalsResp, error) { return fresh, nil })
		close(release)
		<-done
		got, err := c.get(scope, func() (*logicalsResp, error) { t.Error("retired request overwrote current cache"); return nil, nil })
		if err != nil || got != fresh {
			t.Fatal("retired request refilled current cache")
		}
	}
}
